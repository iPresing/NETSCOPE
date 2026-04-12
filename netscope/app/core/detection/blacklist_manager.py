"""Gestionnaire centralisé des blacklists (IPs, Domaines, Termes).

Singleton pattern pour charger et gérer les blacklists au démarrage.

Lessons Learned Epic 1:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Singleton pattern with __new__ like thread_manager.py
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from app.models.blacklist import BlacklistStats, BlacklistType

# CRITICAL: Logger module-level (Lesson Learned Epic 1 - A4)
# NE PAS utiliser current_app.logger ou flask.current_app
logger = logging.getLogger(__name__)


class BlacklistManager:
    """Gestionnaire centralisé des blacklists (IPs, Domaines, Termes).

    Singleton pattern (comme thread_manager.py - Lesson Learned Epic 1).
    Charge les blacklists depuis les fichiers configurés et fournit
    des méthodes pour vérifier les correspondances.
    """

    _instance: BlacklistManager | None = None

    def __new__(cls) -> BlacklistManager:
        """Singleton pattern - une seule instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialisation (appelée une seule fois grâce au singleton)."""
        if self._initialized:
            return
        self._initialized = True

        self._ips: set[str] = set()
        self._domains: set[str] = set()
        self._terms: set[str] = set()
        # Snapshots des sets après chargement fichiers (defaults + txt user)
        # Utilisés par merge_user_entries pour réinitialiser avant fusion
        self._default_ips: set[str] = set()
        self._default_domains: set[str] = set()
        self._default_terms: set[str] = set()
        self._loaded_files: list[str] = []
        # Story 4b.9: mapping filename -> list of entries pour attribution
        # de la source dans l'UI ("default · ips_malware")
        self._entries_by_file: dict[str, list[str]] = {}
        self._base_path: Path | None = None
        logger.debug("BlacklistManager initialized")

    def load_blacklists(self, config: dict, base_path: Path | None = None) -> None:
        """Charge toutes les blacklists depuis la config.

        Args:
            config: Section 'blacklists' de netscope.yaml
            base_path: Chemin de base pour résoudre les chemins relatifs
        """
        logger.info("Loading blacklists from config")

        self._base_path = base_path

        # Reset sets to allow reloading
        self._ips.clear()
        self._domains.clear()
        self._terms.clear()
        self._loaded_files.clear()
        self._entries_by_file.clear()

        # 1. Charger defaults (starter pack) - OBLIGATOIRE
        defaults = config.get("defaults", {})
        self._load_defaults(defaults)

        # 2. Charger user blacklists (extend, pas override)
        paths = config.get("paths", {})
        self._load_user_blacklists(paths)

        # 3. Sauvegarder snapshot des sets fichiers (pour merge_user_entries)
        self._default_ips = set(self._ips)
        self._default_domains = set(self._domains)
        self._default_terms = set(self._terms)

        # 4. Log stats chargées
        stats = self.get_stats()
        logger.info(
            f"Blacklists ready (ips={stats.ips_count}, "
            f"domains={stats.domains_count}, terms={stats.terms_count})"
        )

    def _load_defaults(self, defaults: dict) -> None:
        """Charge les blacklists par défaut (starter pack).

        Args:
            defaults: Section 'defaults' de la config blacklists
        """
        # IPs malware
        if "ips_malware" in defaults:
            self._load_file_to_set(
                defaults["ips_malware"], BlacklistType.IP, self._ips
            )

        # IPs C2
        if "ips_c2" in defaults:
            self._load_file_to_set(
                defaults["ips_c2"], BlacklistType.IP, self._ips
            )

        # Domaines phishing
        if "domains_phishing" in defaults:
            self._load_file_to_set(
                defaults["domains_phishing"], BlacklistType.DOMAIN, self._domains
            )

        # Domaines malware
        if "domains_malware" in defaults:
            self._load_file_to_set(
                defaults["domains_malware"], BlacklistType.DOMAIN, self._domains
            )

        # Termes suspects
        if "terms_suspect" in defaults:
            self._load_file_to_set(
                defaults["terms_suspect"], BlacklistType.TERM, self._terms
            )

    def _load_user_blacklists(self, paths: dict) -> None:
        """Charge les blacklists utilisateur.

        Args:
            paths: Section 'paths' de la config blacklists
        """
        # User IPs
        if "user_ips" in paths:
            self._load_file_to_set(
                paths["user_ips"], BlacklistType.IP, self._ips
            )

        # User domains
        if "user_domains" in paths:
            self._load_file_to_set(
                paths["user_domains"], BlacklistType.DOMAIN, self._domains
            )

        # User terms
        if "user_terms" in paths:
            self._load_file_to_set(
                paths["user_terms"], BlacklistType.TERM, self._terms
            )

    def _load_file_to_set(
        self,
        file_path: str,
        blacklist_type: BlacklistType,
        target_set: set[str],
    ) -> None:
        """Charge un fichier et ajoute les entrées au set cible.

        Args:
            file_path: Chemin vers le fichier .txt
            blacklist_type: Type de blacklist
            target_set: Set cible pour les entrées
        """
        entries = self._load_file(file_path, blacklist_type)
        target_set.update(entries)

    def _load_file(self, file_path: str, blacklist_type: BlacklistType) -> set[str]:
        """Parse fichier .txt: une entrée par ligne, ignore # et lignes vides.

        Args:
            file_path: Chemin vers le fichier .txt
            blacklist_type: Type de blacklist (IP, DOMAIN, TERM)

        Returns:
            Set des entrées valides parsées
        """
        entries: set[str] = set()

        # Résoudre le chemin
        path = Path(file_path)
        if not path.is_absolute() and self._base_path:
            path = self._base_path / file_path

        if not path.exists():
            logger.warning(f"File not found: {file_path} (continuing)")
            return entries

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    # Ignorer commentaires inline
                    line = line.split("#")[0].strip()

                    # Ignorer lignes vides
                    if not line:
                        continue

                    # Normaliser selon le type
                    if blacklist_type == BlacklistType.IP:
                        # Les IPs sont case-insensitive mais on garde tel quel
                        entries.add(line)
                    elif blacklist_type == BlacklistType.DOMAIN:
                        # Domaines en lowercase
                        entries.add(line.lower())
                    else:
                        # Termes gardés tels quels (peuvent être case-sensitive)
                        entries.add(line)

            self._loaded_files.append(str(path))
            # Story 4b.9: conserver la liste des entrées par fichier pour
            # permettre l'attribution de la source dans l'UI
            self._entries_by_file[path.name] = sorted(entries)
            logger.info(
                f"Loaded {path.name} (entries={len(entries)}, type={blacklist_type.value})"
            )

        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")

        return entries

    def get_stats(self) -> BlacklistStats:
        """Retourne statistiques actuelles des blacklists."""
        return BlacklistStats(
            ips_count=len(self._ips),
            domains_count=len(self._domains),
            terms_count=len(self._terms),
            files_loaded=self._loaded_files.copy(),
        )

    def get_active_lists(self) -> dict[str, list[str]]:
        """Retourne les listes actives par type.

        Returns:
            Dictionnaire avec les listes triées par type
        """
        return {
            "ips": sorted(self._ips),
            "domains": sorted(self._domains),
            "terms": sorted(self._terms),
        }

    def get_entries_by_file(self) -> dict[str, list[str]]:
        """Retourne le mapping nom_de_fichier → liste triée d'entrées.

        Story 4b.9 : utilisé par le front pour attribuer la provenance
        (fichier source) à chaque entrée de la blacklist.

        Returns:
            Dict {filename.txt: [entry, ...]} — copie défensive.
        """
        return {k: list(v) for k, v in self._entries_by_file.items()}

    @property
    def ips(self) -> frozenset[str]:
        """Set immutable des IPs blacklistées."""
        return frozenset(self._ips)

    @property
    def domains(self) -> frozenset[str]:
        """Set immutable des domaines blacklistés."""
        return frozenset(self._domains)

    @property
    def terms(self) -> frozenset[str]:
        """Set immutable des termes suspects."""
        return frozenset(self._terms)

    def check_ip(self, ip: str) -> bool:
        """Vérifie si une IP est blacklistée.

        Args:
            ip: Adresse IP à vérifier

        Returns:
            True si l'IP est blacklistée
        """
        return ip in self._ips

    def check_domain(self, domain: str) -> bool:
        """Vérifie si un domaine est blacklisté.

        Args:
            domain: Domaine à vérifier

        Returns:
            True si le domaine est blacklisté
        """
        return domain.lower() in self._domains

    def check_term(self, text: str) -> list[str]:
        """Vérifie si un texte contient des termes suspects (case-insensitive).

        Args:
            text: Texte à analyser

        Returns:
            Liste des termes suspects trouvés
        """
        found = []
        text_lower = text.lower()
        for term in self._terms:
            if term.lower() in text_lower:
                found.append(term)
        return found

    def get_defaults_metadata(self) -> list[dict]:
        """Retourne les métadonnées des fichiers .meta.yaml du dossier defaults.

        Parse chaque fichier `<nom>.meta.yaml` présent à côté des fichiers .txt
        chargés par _load_defaults. Les fichiers absents ou mal formés
        n'interrompent PAS le chargement : un warning est loggé et l'entrée
        est omise du résultat (rétrocompatibilité story 4b.9 AC2).

        Returns:
            Liste de dicts avec les clés : name, category, description,
            sources (list[{name,url,license}]), last_updated, entries_count,
            file (nom du .txt associé).
        """
        import yaml

        results: list[dict] = []

        # Déterminer les noms de fichiers .txt loadés via defaults
        defaults_files: list[Path] = []
        for loaded in self._loaded_files:
            path = Path(loaded)
            if "blacklists_defaults" in path.parts and path.suffix == ".txt":
                defaults_files.append(path)

        for txt_path in defaults_files:
            meta_path = txt_path.with_suffix(".meta.yaml")
            file_name = txt_path.name

            if not meta_path.exists():
                logger.warning(
                    f"No .meta.yaml for default blacklist (file={file_name})"
                )
                continue

            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not isinstance(data, dict):
                    logger.warning(
                        f"Invalid .meta.yaml content (file={meta_path.name})"
                    )
                    continue

                # Recomputer entries_count depuis le fichier .txt réel pour
                # éviter les désynchronisations si le .txt est édité à la main
                actual_count = self._count_txt_entries(txt_path)

                meta: dict = {
                    "name": str(data.get("name", txt_path.stem)),
                    "category": str(data.get("category", "")),
                    "description": str(data.get("description", "")),
                    "sources": list(data.get("sources") or []),
                    "last_updated": str(data.get("last_updated", "")),
                    "entries_count": actual_count,
                    "file": file_name,
                }
                results.append(meta)

            except Exception as e:
                logger.warning(
                    f"Failed to parse .meta.yaml (file={meta_path.name}, "
                    f"error={e})"
                )

        return results

    def _count_txt_entries(self, txt_path: Path) -> int:
        """Compte le nombre d'entrées valides dans un fichier .txt blacklist.

        Ignore les lignes vides et les commentaires. Utilisé pour synchroniser
        entries_count sans relire tout le dataset via load_blacklists.

        Args:
            txt_path: Chemin vers le fichier .txt

        Returns:
            Nombre de lignes non-commentaires et non-vides (0 si lecture impossible)
        """
        try:
            count = 0
            with open(txt_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        count += 1
            return count
        except OSError as e:
            logger.warning(f"Cannot count entries in {txt_path.name}: {e}")
            return 0

    def merge_user_entries(self, user_entries) -> None:
        """Fusionne les entrées utilisateur dans les sets en mémoire.

        Réinitialise d'abord les sets au snapshot defaults (chargé depuis
        les fichiers), puis ajoute les entrées utilisateur par-dessus.
        Cela garantit que les suppressions sont répercutées immédiatement.

        Args:
            user_entries: Liste de UserBlacklistEntry à fusionner
        """
        # Réinitialiser aux defaults fichiers (supprime les user entries précédentes)
        self._ips = set(self._default_ips)
        self._domains = set(self._default_domains)
        self._terms = set(self._default_terms)

        # Ajouter les entrées utilisateur courantes par-dessus
        for entry in user_entries:
            if entry.entry_type == BlacklistType.IP:
                self._ips.add(entry.value)
            elif entry.entry_type == BlacklistType.DOMAIN:
                self._domains.add(entry.value.lower())
            elif entry.entry_type == BlacklistType.TERM:
                self._terms.add(entry.value)

        logger.info(
            f"User entries merged (count={len(user_entries)}, "
            f"total_ips={len(self._ips)}, total_domains={len(self._domains)}, "
            f"total_terms={len(self._terms)})"
        )


# Global singleton instance
_blacklist_manager: BlacklistManager | None = None


def get_blacklist_manager() -> BlacklistManager:
    """Get the global BlacklistManager instance.

    Creates the instance on first call.

    Returns:
        BlacklistManager singleton instance
    """
    global _blacklist_manager

    if _blacklist_manager is None:
        _blacklist_manager = BlacklistManager()

    return _blacklist_manager


def reset_blacklist_manager() -> None:
    """Reset the global BlacklistManager instance (for testing)."""
    global _blacklist_manager
    if _blacklist_manager is not None:
        _blacklist_manager._initialized = False
        _blacklist_manager._ips.clear()
        _blacklist_manager._domains.clear()
        _blacklist_manager._terms.clear()
        _blacklist_manager._default_ips.clear()
        _blacklist_manager._default_domains.clear()
        _blacklist_manager._default_terms.clear()
        _blacklist_manager._loaded_files.clear()
        _blacklist_manager._entries_by_file.clear()
    _blacklist_manager = None
    BlacklistManager._instance = None


# =============================================================================
# HOT-RELOAD FILE WATCHER
# =============================================================================

class BlacklistFileWatcher:
    """File watcher for automatic blacklist reload on file changes.

    Uses watchdog library to monitor blacklist directories for changes.
    When a .txt file is modified, triggers a reload of all blacklists.

    Usage:
        watcher = BlacklistFileWatcher(config, base_path)
        watcher.start()
        # ... application runs ...
        watcher.stop()
    """

    def __init__(
        self,
        config: dict,
        base_path: Path | None = None,
        debounce_seconds: float = 1.0,
    ) -> None:
        """Initialize the file watcher.

        Args:
            config: Blacklist configuration dict (from netscope.yaml)
            base_path: Base path for resolving relative paths
            debounce_seconds: Delay before reload to debounce rapid changes
        """
        self._config = config
        self._base_path = base_path
        self._debounce_seconds = debounce_seconds
        self._observer: Observer | None = None
        self._running = False
        self._last_reload_time: float = 0
        logger.debug("BlacklistFileWatcher initialized")

    def start(self) -> bool:
        """Start watching blacklist directories for changes.

        Returns:
            True if watcher started successfully, False otherwise
        """
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler, FileModifiedEvent

            # Get directories to watch
            watch_dirs = self._get_watch_directories()
            if not watch_dirs:
                logger.warning("No blacklist directories found to watch")
                return False

            # Create event handler
            handler = _BlacklistChangeHandler(
                self._config,
                self._base_path,
                self._debounce_seconds,
            )

            # Create and configure observer
            self._observer = Observer()
            for directory in watch_dirs:
                if directory.exists():
                    self._observer.schedule(handler, str(directory), recursive=False)
                    logger.info(f"Watching directory for changes (path={directory})")

            # Start observer thread
            self._observer.start()
            self._running = True
            logger.info("Blacklist hot-reload watcher started")
            return True

        except ImportError:
            logger.error("watchdog library not installed - hot-reload disabled")
            return False
        except Exception as e:
            logger.error(f"Failed to start file watcher (error={e})")
            return False

    def stop(self) -> None:
        """Stop watching for file changes."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5.0)
            self._observer = None
            self._running = False
            logger.info("Blacklist hot-reload watcher stopped")

    @property
    def is_running(self) -> bool:
        """Check if the watcher is currently running."""
        return self._running

    def _get_watch_directories(self) -> list[Path]:
        """Get list of directories to watch for changes.

        Returns:
            List of Path objects for directories containing blacklist files
        """
        directories: set[Path] = set()

        # Get directories from defaults config
        defaults = self._config.get("defaults", {})
        for file_path in defaults.values():
            path = self._resolve_path(file_path)
            if path and path.parent.exists():
                directories.add(path.parent)

        # Get directories from user paths config
        paths = self._config.get("paths", {})
        for file_path in paths.values():
            path = self._resolve_path(file_path)
            if path and path.parent.exists():
                directories.add(path.parent)

        return list(directories)

    def _resolve_path(self, file_path: str) -> Path | None:
        """Resolve a file path, handling relative paths.

        Args:
            file_path: Path string to resolve

        Returns:
            Resolved Path object or None if invalid
        """
        try:
            path = Path(file_path)
            if not path.is_absolute() and self._base_path:
                path = self._base_path / file_path
            return path
        except Exception:
            return None


class _BlacklistChangeHandler:
    """Internal handler for blacklist file change events.

    Uses trailing-edge debounce: waits for changes to stop before reloading.
    This ensures all rapid changes are captured in a single reload.
    """

    def __init__(
        self,
        config: dict,
        base_path: Path | None,
        debounce_seconds: float,
    ) -> None:
        self._config = config
        self._base_path = base_path
        self._debounce_seconds = debounce_seconds
        self._pending_timer: threading.Timer | None = None
        self._timer_lock = threading.Lock()

    def dispatch(self, event) -> None:
        """Handle file system events.

        Args:
            event: Watchdog file system event
        """
        # Only handle .txt file modifications
        if not hasattr(event, 'src_path'):
            return

        src_path = str(event.src_path)
        if not src_path.endswith('.txt'):
            return

        # Skip if event is not a modification
        event_type = getattr(event, 'event_type', None)
        if event_type not in ('modified', 'created', 'deleted'):
            return

        # Schedule a debounced reload (trailing-edge debounce)
        self._schedule_reload(Path(src_path).name)

    def _schedule_reload(self, filename: str) -> None:
        """Schedule a reload after debounce period.

        If a reload is already scheduled, cancel it and reschedule.
        This implements trailing-edge debounce.

        Args:
            filename: Name of the file that changed (for logging)
        """
        with self._timer_lock:
            # Cancel any pending reload
            if self._pending_timer is not None:
                self._pending_timer.cancel()
                self._pending_timer = None

            # Schedule new reload after debounce period
            self._pending_timer = threading.Timer(
                self._debounce_seconds,
                self._do_reload,
                args=[filename],
            )
            self._pending_timer.daemon = True
            self._pending_timer.start()

    def _do_reload(self, filename: str) -> None:
        """Execute the actual reload.

        Args:
            filename: Name of the file that triggered the reload
        """
        with self._timer_lock:
            self._pending_timer = None

        logger.info(f"Blacklist file changed, reloading (file={filename})")

        try:
            manager = get_blacklist_manager()
            manager.load_blacklists(self._config, base_path=self._base_path)
            stats = manager.get_stats()
            logger.info(
                f"Blacklists hot-reloaded (ips={stats.ips_count}, "
                f"domains={stats.domains_count}, terms={stats.terms_count})"
            )
        except Exception as e:
            logger.error(f"Hot-reload failed (error={e})")


# Global file watcher instance
_file_watcher: BlacklistFileWatcher | None = None


def start_blacklist_watcher(
    config: dict,
    base_path: Path | None = None,
) -> BlacklistFileWatcher | None:
    """Start the global blacklist file watcher.

    Args:
        config: Blacklist configuration dict
        base_path: Base path for resolving relative paths

    Returns:
        BlacklistFileWatcher instance if started, None if failed
    """
    global _file_watcher

    # Check if hot-reload is enabled in config
    if not config.get("reload_on_change", False):
        logger.info("Blacklist hot-reload disabled in config")
        return None

    # Stop existing watcher if running
    if _file_watcher is not None:
        _file_watcher.stop()

    # Create and start new watcher
    _file_watcher = BlacklistFileWatcher(config, base_path)
    if _file_watcher.start():
        return _file_watcher
    else:
        _file_watcher = None
        return None


def stop_blacklist_watcher() -> None:
    """Stop the global blacklist file watcher."""
    global _file_watcher
    if _file_watcher is not None:
        _file_watcher.stop()
        _file_watcher = None


def get_blacklist_watcher() -> BlacklistFileWatcher | None:
    """Get the global blacklist file watcher instance.

    Returns:
        BlacklistFileWatcher instance or None if not running
    """
    return _file_watcher
