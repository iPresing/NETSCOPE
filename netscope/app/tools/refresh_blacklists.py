"""CLI de rafraîchissement des blacklists par défaut NETSCOPE.

Story 4b.9 — Enrichissement Blacklists Sources.

Ce script télécharge les sources publiques listées dans
`data/blacklists_defaults/manifest.yaml`, parse chaque flux, valide/dédoublonne
les entrées, et réécrit atomiquement les fichiers `.txt` + `.meta.yaml`
correspondants.

**Important** : ce module ne doit PAS être importé par `app/__init__.py` ni par
les blueprints. Il est destiné à une exécution manuelle :

    python -m app.tools.refresh_blacklists [--source <name>] [--dry-run]

Hors-scope (AC5 story 4b.9) :
- Pas de cron, pas d'appel au démarrage, pas de fetch runtime.
- Pas d'import dans l'arborescence `app.blueprints` ou `app.core`.

Dépendances : uniquement stdlib (urllib) + PyYAML (déjà présent). La
bibliothèque `requests` n'est volontairement PAS utilisée pour ne pas
introduire une nouvelle dépendance au projet.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

# Logger module-level (règle Epic 1 #2)
logger = logging.getLogger("netscope.tools.refresh_blacklists")

# User-agent explicite requis par AC5
USER_AGENT = "NETSCOPE-blacklist-refresher/1.0"
HTTP_TIMEOUT_SECONDS = 30

# Regex importées du modèle canonique pour éviter la duplication
# (app.models.blacklist est un module pur Python, sans dépendance Flask)
from app.models.blacklist import _IP_RE as IP_RE, _DOMAIN_RE as DOMAIN_RE

RESERVED_TLDS = (".local", ".localhost", ".example", ".invalid", ".test")


@dataclass
class SourceSpec:
    """Une entrée du manifest.yaml."""

    name: str
    url: str
    parser: str
    target: str
    max_entries: int
    license: str


@dataclass
class RefreshResult:
    """Résultat du traitement d'une source."""

    source: SourceSpec
    fetched: int = 0
    accepted: int = 0
    rejected: int = 0
    errors: list[str] = field(default_factory=list)


def _find_defaults_dir() -> Path:
    """Retourne le chemin du dossier `data/blacklists_defaults/`.

    Raises:
        FileNotFoundError: si le dossier n'est pas trouvé.
    """
    # app/tools/refresh_blacklists.py → app/tools/ → app/ → netscope/ → netscope/data/...
    module_path = Path(__file__).resolve()
    project_root = module_path.parent.parent.parent  # netscope/
    defaults_dir = project_root / "data" / "blacklists_defaults"
    if not defaults_dir.is_dir():
        raise FileNotFoundError(
            f"Dossier blacklists_defaults introuvable: {defaults_dir}"
        )
    return defaults_dir


def load_manifest(defaults_dir: Path) -> list[SourceSpec]:
    """Charge manifest.yaml et retourne la liste des SourceSpec."""
    manifest_path = defaults_dir / "manifest.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.yaml manquant: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    sources_raw = data.get("sources") or []
    sources: list[SourceSpec] = []
    for raw in sources_raw:
        if not isinstance(raw, dict):
            continue
        try:
            sources.append(
                SourceSpec(
                    name=str(raw["name"]),
                    url=str(raw["url"]),
                    parser=str(raw["parser"]),
                    target=str(raw["target"]),
                    max_entries=int(raw.get("max_entries", 500)),
                    license=str(raw.get("license", "unknown")),
                )
            )
        except (KeyError, ValueError, TypeError) as e:
            logger.error(f"Manifest entry invalide ({raw}): {e}")
    return sources


def fetch(url: str) -> str:
    """Télécharge une URL HTTPS et retourne le corps texte.

    Args:
        url: URL à télécharger (doit commencer par https://).

    Returns:
        Corps de la réponse décodé en UTF-8 (errors='replace').

    Raises:
        ValueError: si l'URL n'est pas HTTPS.
        urllib.error.URLError: en cas d'erreur réseau/HTTP.
    """
    if not url.startswith("https://"):
        raise ValueError(f"Seules les URLs HTTPS sont autorisées: {url}")

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS, context=ctx) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="replace")


def _is_usable_ip(value: str) -> bool:
    """Retourne True si la chaîne est une IP publique valide.

    Exclut : IPs privées (RFC1918), loopback, link-local, multicast, réservées.
    """
    if not IP_RE.match(value):
        return False
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return False
    return True


def _is_usable_domain(value: str) -> bool:
    """Retourne True si la chaîne est un domaine public valide.

    Exclut : TLDs réservés, longueur invalide, absence de lettre.
    """
    if len(value) < 3 or len(value) > 253:
        return False
    if not DOMAIN_RE.match(value):
        return False
    if not any(c.isalpha() for c in value):
        return False
    low = value.lower()
    if any(low.endswith(t) for t in RESERVED_TLDS):
        return False
    return True


def parse_plain_text_ip(body: str) -> list[str]:
    """Parse un flux texte avec une IP par ligne (# pour commentaires).

    Pour les plages `x.x.x.x/N`, seule l'adresse réseau est extraite si elle
    est unitaire (/32). Les plages plus larges sont ignorées.
    """
    results: list[str] = []
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # Supporter la notation CIDR éventuelle (FireHOL)
        if "/" in line:
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.prefixlen == 32 and isinstance(net.network_address, ipaddress.IPv4Address):
                candidate = str(net.network_address)
            else:
                continue
        else:
            candidate = line.split()[0]  # Feodo peut ajouter des colonnes
        if _is_usable_ip(candidate):
            results.append(candidate)
    return results


def parse_plain_text_domain(body: str) -> list[str]:
    """Parse un flux texte avec un domaine par ligne (# pour commentaires).

    Supporte les formats :
      - `example.com`
      - `0.0.0.0 example.com` (hosts-file style)
      - `||example.com^` (adblock)
    """
    results: list[str] = []
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # Format hosts-file
        if line.startswith(("0.0.0.0", "127.0.0.1")):
            parts = line.split()
            if len(parts) >= 2:
                line = parts[1]
            else:
                continue
        # Format adblock ||domain^
        if line.startswith("||"):
            line = line[2:]
            line = line.split("^", 1)[0]
            line = line.split("/", 1)[0]
        line = line.lower()
        if _is_usable_domain(line):
            results.append(line)
    return results


PARSERS = {
    "plain_text_ip": parse_plain_text_ip,
    "plain_text_domain": parse_plain_text_domain,
}


def _read_existing_entries(path: Path) -> list[str]:
    """Lit les entrées existantes d'un .txt en conservant l'ordre, sans commentaires."""
    if not path.exists():
        return []
    entries: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if line:
                entries.append(line)
    return entries


def _atomic_write(path: Path, content: str) -> None:
    """Écriture atomique via fichier temporaire + os.replace (TOCTOU-safe, règle #19)."""
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    # delete=False car on veut contrôler le rename
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(directory),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as tmp:
            tmp.write(content)
        os.replace(tmp_name, path)
    except Exception:
        # Nettoyage best-effort
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _format_txt_output(
    target_name: str,
    sources_used: list[SourceSpec],
    entries: list[str],
) -> str:
    """Formatte le contenu d'un fichier .txt avec en-tête explicatif."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"# NETSCOPE Starter Pack - {target_name}",
        "# Rafraîchi par app.tools.refresh_blacklists (story 4b.9)",
        "# Sources:",
    ]
    for s in sources_used:
        lines.append(f"#   - {s.name} ({s.license}) {s.url}")
    lines.append(f"# Dernière mise à jour: {now}")
    lines.append("")
    lines.extend(entries)
    lines.append("")  # newline final
    return "\n".join(lines)


def _update_meta_yaml(
    defaults_dir: Path,
    target_txt: str,
    sources_used: list[SourceSpec],
    entries_count: int,
) -> None:
    """Met à jour le fichier .meta.yaml associé : entries_count, last_updated, sources."""
    meta_path = defaults_dir / Path(target_txt).with_suffix(".meta.yaml").name
    if not meta_path.exists():
        logger.warning(f"No .meta.yaml to update: {meta_path.name}")
        return

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = yaml.safe_load(f) or {}

    meta["entries_count"] = entries_count
    meta["last_updated"] = datetime.now(timezone.utc).isoformat()
    meta["sources"] = [
        {"name": s.name, "url": s.url, "license": s.license}
        for s in sources_used
    ]

    content = yaml.safe_dump(meta, allow_unicode=True, sort_keys=False)
    _atomic_write(meta_path, content)


def refresh(
    defaults_dir: Path,
    source_filter: str | None = None,
    dry_run: bool = False,
) -> list[RefreshResult]:
    """Rafraîchit les fichiers .txt à partir des sources du manifest.

    Args:
        defaults_dir: Dossier contenant manifest.yaml + fichiers .txt/.meta.yaml.
        source_filter: Si fourni, ne traiter que la source de ce nom.
        dry_run: Si True, ne pas écrire sur le disque.

    Returns:
        Liste de RefreshResult par source traitée.
    """
    sources = load_manifest(defaults_dir)
    if source_filter:
        sources = [s for s in sources if s.name == source_filter]
        if not sources:
            raise ValueError(f"Source inconnue: {source_filter}")

    # Regrouper par fichier cible
    by_target: dict[str, list[tuple[SourceSpec, list[str]]]] = {}
    results: list[RefreshResult] = []

    for source in sources:
        result = RefreshResult(source=source)
        try:
            body = fetch(source.url)
            result.fetched = body.count("\n")
        except (urllib.error.URLError, ValueError, TimeoutError) as e:
            msg = f"Fetch échoué pour {source.name}: {e}"
            logger.error(msg)
            result.errors.append(msg)
            results.append(result)
            continue

        parser_func = PARSERS.get(source.parser)
        if parser_func is None:
            msg = f"Parser inconnu: {source.parser}"
            logger.error(msg)
            result.errors.append(msg)
            results.append(result)
            continue

        parsed = parser_func(body)
        if len(parsed) > source.max_entries:
            parsed = parsed[: source.max_entries]
        result.accepted = len(parsed)
        by_target.setdefault(source.target, []).append((source, parsed))
        results.append(result)

    # Écriture par fichier cible
    for target, groups in by_target.items():
        # Sécurité : Path(target).name strip les composants de répertoire
        # pour empêcher le path traversal via un manifest malveillant
        safe_target = Path(target).name
        if safe_target != target:
            logger.warning(f"Path traversal détecté dans target={target!r}, sanitisé en {safe_target!r}")
        txt_path = defaults_dir / safe_target

        # Partir des entrées existantes pour ne pas les écraser
        merged: list[str] = list(_read_existing_entries(txt_path))
        merged_set: set[str] = set(merged)
        sources_used: list[SourceSpec] = []
        for source, entries in groups:
            sources_used.append(source)
            for e in entries:
                if e not in merged_set:
                    merged.append(e)
                    merged_set.add(e)

        content = _format_txt_output(safe_target, sources_used, merged)

        if dry_run:
            logger.info(
                f"[dry-run] {safe_target}: {len(merged)} entrées (base {len(_read_existing_entries(txt_path))})"
            )
            continue

        _atomic_write(txt_path, content)
        _update_meta_yaml(defaults_dir, safe_target, sources_used, len(merged))
        logger.info(f"{safe_target}: {len(merged)} entrées écrites")

    return results


def build_parser() -> argparse.ArgumentParser:
    """Construit le parser argparse du CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m app.tools.refresh_blacklists",
        description=(
            "Rafraîchit les blacklists par défaut NETSCOPE depuis les "
            "sources publiques du manifest.yaml."
        ),
    )
    parser.add_argument(
        "--source",
        metavar="NAME",
        help="Ne traiter qu'une source spécifique (ex: feodo_tracker).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Afficher les modifications sans écrire.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Mode verbose (logs DEBUG).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point CLI.

    Returns:
        0 en cas de succès, 1 si au moins une source a échoué, 2 si fatale.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        defaults_dir = _find_defaults_dir()
    except FileNotFoundError as e:
        logger.error(str(e))
        return 2

    try:
        results = refresh(
            defaults_dir,
            source_filter=args.source,
            dry_run=args.dry_run,
        )
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Erreur fatale: {e}")
        return 2

    error_count = sum(1 for r in results if r.errors)
    total = len(results)
    logger.info(
        f"Terminé: {total - error_count}/{total} sources OK, "
        f"{error_count} erreur(s)"
    )
    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
