"""CLI tools for NETSCOPE (non importés par l'application Flask).

Ce dossier contient des scripts utilitaires destinés à être lancés
manuellement depuis la ligne de commande (via `python -m app.tools.<module>`).

Aucun module de ce dossier ne doit être importé depuis `app/__init__.py`
ni depuis les blueprints : cela briserait l'isolation runtime et pourrait
introduire des dépendances non désirées au démarrage (story 4b.9, règle #22).
"""
