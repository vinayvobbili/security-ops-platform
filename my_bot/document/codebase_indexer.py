"""
Codebase Indexer for the Windows triage agent

Indexes a curated set of Python and Markdown source files into a dedicated
ChromaDB collection (chroma_win_ai) for the the Windows triage agent tutor bot.

The indexed set is intentionally explicit — only directories listed in
CURATED_DIRS are walked. This eliminates any risk of indexing .env,
.secrets.age, or other sensitive files.

Rebuild is triggered weekly by scheduler.py. Can also be run manually:
    python my_bot/document/codebase_indexer.py
"""

import hashlib
import logging
import os
from pathlib import Path
from typing import List, Optional

import os

import chromadb
from langchain_community.document_loaders import TextLoader
from langchain_core.documents import Document

try:
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain.text_splitter import Language
except ImportError:
    from langchain_text_splitters import RecursiveCharacterTextSplitter, Language

import yaml

from my_bot.document.document_processor import OllamaEmbeddingFunction

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# XSOAR YAML preprocessor — converts raw YAML into clean, readable text
# ---------------------------------------------------------------------------

# Keys that are pure noise for understanding what a playbook/script does
_XSOAR_NOISE_KEYS = {
    "view", "timertriggers", "quietmode", "isoversize",
    "isautoswitchedtoquietmode", "ignoreworker", "continueonerrortype",
    "contentitemexportablefields", "system", "pswd", "runas", "runonce",
    "scripttarget", "engineinfo", "mainengineinfo", "enabled",
}


def _summarize_xsoar_yaml(path: Path) -> Optional[str]:
    """Parse an XSOAR YAML and return a clean human-readable summary.

    Returns None if the file isn't a recognizable XSOAR content item,
    in which case the caller should fall back to raw text loading.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None
    except Exception:
        return None

    filename = path.name

    # --- Playbooks ---
    if "tasks" in data and isinstance(data["tasks"], dict):
        return _summarize_playbook(data, filename)

    # --- Automations / Scripts ---
    if "script" in data and "commonfields" in data:
        return _summarize_automation(data, filename)

    # --- Integrations ---
    if "configuration" in data and "script" in data:
        return _summarize_integration(data, filename)

    # --- Classifiers, Mappers, Layouts, etc. — index name + description only ---
    if "name" in data:
        return _summarize_generic(data, filename)

    return None


def _summarize_playbook(data: dict, filename: str) -> str:
    """Extract playbook name, description, inputs/outputs, and task flow."""
    lines = []
    name = data.get("name", filename)
    lines.append(f"# Playbook: {name}")
    lines.append(f"File: {filename}")

    desc = data.get("description")
    if desc:
        lines.append(f"\n## Description\n{desc}")

    # Inputs
    inputs = data.get("inputs")
    if inputs:
        lines.append("\n## Inputs")
        for inp in inputs:
            if isinstance(inp, dict):
                key = inp.get("key", "?")
                idesc = inp.get("description", "")
                req = " (required)" if inp.get("required") else ""
                lines.append(f"- **{key}**{req}: {idesc}" if idesc else f"- **{key}**{req}")

    # Outputs
    outputs = data.get("outputs")
    if outputs:
        lines.append("\n## Outputs")
        for out in outputs:
            if isinstance(out, dict):
                key = out.get("contextPath", out.get("key", "?"))
                odesc = out.get("description", "")
                lines.append(f"- **{key}**: {odesc}" if odesc else f"- **{key}**")

    # Tasks — the core of the playbook
    tasks = data.get("tasks", {})
    start_id = data.get("starttaskid")
    lines.append(f"\n## Tasks ({len(tasks)} total)")

    for tid, task_data in sorted(tasks.items(), key=lambda x: str(x[0])):
        task_inner = task_data.get("task", {})
        task_name = task_inner.get("name", "")
        task_type = task_data.get("type", task_inner.get("type", ""))
        task_desc = task_inner.get("description", "")
        is_command = task_inner.get("iscommand", False)
        brand = task_inner.get("brand", "")
        playbook_id_name = task_inner.get("name", "")
        script_name = task_inner.get("scriptName", "")

        # Next tasks (flow)
        nexttasks = task_data.get("nexttasks", {})
        next_flow = []
        for condition, targets in nexttasks.items():
            if targets:
                target_str = ", ".join(str(t) for t in targets)
                if condition == "#none#":
                    next_flow.append(f"→ task {target_str}")
                elif condition == "#default#":
                    next_flow.append(f"(default) → task {target_str}")
                else:
                    next_flow.append(f"({condition}) → task {target_str}")

        # Conditions
        conditions = task_data.get("conditions", [])
        condition_labels = []
        for cond in conditions:
            if isinstance(cond, dict):
                condition_labels.append(cond.get("label", ""))

        # Forms (analyst input)
        form = task_data.get("form")
        form_fields = []
        if form and isinstance(form, dict):
            for q in form.get("questions", []):
                if isinstance(q, dict):
                    label = q.get("labelarg", {})
                    if isinstance(label, dict):
                        label = label.get("simple", "")
                    field = q.get("fieldassociated", "")
                    options = q.get("options", [])
                    opts_str = ""
                    if options and any(o for o in options):
                        opts_str = f" Options: {', '.join(str(o) for o in options if o)}"
                    form_fields.append(f"{label} [field: {field}]{opts_str}" if field else str(label))

        # Script args
        scriptargs = task_data.get("scriptarguments", {})

        # Build task line
        parts = [f"\n### Task {tid}"]
        if task_name:
            parts.append(f"**{task_name}**")
        if task_type:
            parts.append(f"Type: {task_type}")
        if task_desc and task_desc != task_name:
            parts.append(f"Description: {task_desc}")
        if is_command and script_name:
            parts.append(f"Command: {script_name} (integration: {brand})" if brand else f"Command: {script_name}")
        elif is_command and brand:
            parts.append(f"Integration: {brand}")
        if task_type == "playbook":
            parts.append(f"Sub-playbook: {playbook_id_name}")
        if form_fields:
            parts.append("Analyst input: " + "; ".join(form_fields))
        if condition_labels:
            parts.append("Conditions: " + ", ".join(c for c in condition_labels if c))
        if next_flow:
            parts.append("Flow: " + " | ".join(next_flow))
        if scriptargs:
            arg_summary = []
            for arg_name, arg_val in scriptargs.items():
                if isinstance(arg_val, dict):
                    simple = arg_val.get("simple", "")
                    if simple:
                        arg_summary.append(f"{arg_name}={simple}")
                    else:
                        arg_summary.append(arg_name)
                else:
                    arg_summary.append(f"{arg_name}={arg_val}")
            if arg_summary:
                parts.append("Args: " + ", ".join(arg_summary[:10]))

        lines.append("\n".join(parts))

    return "\n".join(lines)


def _summarize_automation(data: dict, filename: str) -> str:
    """Extract automation/script name, description, args, tags, and script type."""
    lines = []
    name = data.get("name", filename)
    lines.append(f"# Automation: {name}")
    lines.append(f"File: {filename}")

    comment = data.get("comment", "")
    if comment:
        lines.append(f"\n## Description\n{comment}")

    script_type = data.get("type", "")
    if script_type:
        lines.append(f"Language: {script_type}")

    tags = data.get("tags")
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")

    # Arguments
    args = data.get("args")
    if args:
        lines.append("\n## Arguments")
        for arg in args:
            if isinstance(arg, dict):
                aname = arg.get("name", "?")
                adesc = arg.get("description", "")
                req = " (required)" if arg.get("required") else ""
                default = arg.get("defaultValue", "")
                default_str = f" [default: {default}]" if default else ""
                lines.append(f"- **{aname}**{req}{default_str}: {adesc}" if adesc else f"- **{aname}**{req}{default_str}")

    # Outputs
    outputs = data.get("outputs")
    if outputs:
        lines.append("\n## Outputs")
        for out in outputs:
            if isinstance(out, dict):
                key = out.get("contextPath", "?")
                odesc = out.get("description", "")
                lines.append(f"- **{key}**: {odesc}" if odesc else f"- **{key}**")

    # Include script source (truncated for very large scripts)
    script = data.get("script", "")
    if isinstance(script, str) and script.strip():
        # Skip binary/encoded content
        if len(script) > 10000:
            script = script[:10000] + "\n... (truncated)"
        lines.append(f"\n## Script\n```\n{script}\n```")

    return "\n".join(lines)


def _summarize_integration(data: dict, filename: str) -> str:
    """Extract integration name, description, commands, and configuration."""
    lines = []
    name = data.get("name", data.get("display", filename))
    lines.append(f"# Integration: {name}")
    lines.append(f"File: {filename}")

    desc = data.get("description", "")
    if desc:
        lines.append(f"\n## Description\n{desc}")

    category = data.get("category", "")
    if category:
        lines.append(f"Category: {category}")

    # Configuration params
    config = data.get("configuration", [])
    if config:
        lines.append("\n## Configuration")
        for param in config:
            if isinstance(param, dict):
                pname = param.get("name", param.get("display", "?"))
                pdesc = param.get("additionalinfo", param.get("display", ""))
                req = " (required)" if param.get("required") else ""
                lines.append(f"- **{pname}**{req}: {pdesc}" if pdesc else f"- **{pname}**{req}")

    # Commands
    script_data = data.get("script", {})
    if isinstance(script_data, dict):
        commands = script_data.get("commands", [])
        if commands:
            lines.append(f"\n## Commands ({len(commands)})")
            for cmd in commands:
                if isinstance(cmd, dict):
                    cname = cmd.get("name", "?")
                    cdesc = cmd.get("description", "")
                    lines.append(f"- **{cname}**: {cdesc}" if cdesc else f"- **{cname}**")

    return "\n".join(lines)


def _summarize_generic(data: dict, filename: str) -> str:
    """Minimal summary for classifiers, layouts, incident types, etc."""
    lines = []
    name = data.get("name", filename)
    kind = data.get("type", data.get("kind", "Content Item"))
    lines.append(f"# {kind}: {name}")
    lines.append(f"File: {filename}")

    desc = data.get("description", "")
    if desc:
        lines.append(f"\n{desc}")

    return "\n".join(lines)

COLLECTION_NAME = "codebase_documents"  # IR source files
XSOAR_COLLECTION_NAME = "xsoar_documents"  # XSOAR automation YAMLs

# Directories to index, relative to project root.
# Add or remove entries here to tune what the Windows triage agent knows about.
CURATED_DIRS = [
    "webex_bots",
    "my_bot",
    "services",
    "src",
    "docs",
]

# Top-level files to index (relative to project root)
CURATED_FILES = [
    "my_config.py",
]

# File extensions to index
INDEXED_EXTENSIONS = {".py", ".md"}

# Extensions to index from external repos (e.g. XSOAR YAML automations)
EXTERNAL_INDEXED_EXTENSIONS = {".yml", ".yaml"}

# Directories to skip even if they appear under a curated path
SKIP_DIRS = {"__pycache__", ".git", "node_modules", "chroma_documents", "chroma_win_ai"}


def _project_root() -> Path:
    # my_bot/document/codebase_indexer.py -> two levels up -> project root
    return Path(__file__).parent.parent.parent


def _pull_xsoar_repo(repo_path: Path) -> None:
    """Pull latest commits from the XSOAR Azure DevOps repo before indexing."""
    import subprocess
    pat = os.environ.get("AZDO_PERSONAL_ACCESS_TOKEN")
    if not pat:
        logger.warning("AZDO_PERSONAL_ACCESS_TOKEN not set — skipping XSOAR git pull")
        return
    remote_url = (
        f"https://the company-US:{pat}@dev.azure.com/the company-US/"
        f"the company-Cyber-Platforms/_git/the companyCyberPlatformsXSOAR.git"
    )
    try:
        # Update stored remote URL so a rotated PAT always works
        subprocess.run(
            ["git", "remote", "set-url", "origin", remote_url],
            cwd=str(repo_path), capture_output=True, timeout=30,
        )
        result = subprocess.run(
            ["git", "pull", "--depth=1", "--no-rebase"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            logger.info(f"XSOAR repo pulled: {result.stdout.strip() or 'already up to date'}")
        else:
            logger.warning(f"XSOAR git pull returned {result.returncode}: {result.stderr.strip()[:200]}")
    except Exception as e:
        logger.warning(f"XSOAR repo pull failed: {e}")


def _collect_ir_files() -> List[Path]:
    """Walk CURATED_DIRS and top-level CURATED_FILES for the IR codebase index."""
    root = _project_root()
    files: List[Path] = []

    for rel_dir in CURATED_DIRS:
        target = root / rel_dir
        if not target.exists():
            logger.warning(f"Curated dir not found, skipping: {target}")
            continue
        for path in target.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix in INDEXED_EXTENSIONS:
                files.append(path)

    for rel_file in CURATED_FILES:
        target = root / rel_file
        if target.exists() and target.suffix in INDEXED_EXTENSIONS:
            files.append(target)
        else:
            logger.warning(f"Curated file not found or wrong type, skipping: {target}")

    return files


def _collect_xsoar_files() -> List[Path]:
    """Collect YAML automation files from the XSOAR repo (WINAI_XSOAR_REPO_PATH)."""
    xsoar_path = os.environ.get("WINAI_XSOAR_REPO_PATH")
    if not xsoar_path:
        logger.warning("WINAI_XSOAR_REPO_PATH not set — XSOAR index will be empty")
        return []
    xsoar_dir = Path(xsoar_path)
    if not xsoar_dir.exists():
        logger.warning(f"WINAI_XSOAR_REPO_PATH not found: {xsoar_dir}")
        return []
    files: List[Path] = []
    for path in xsoar_dir.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix in EXTERNAL_INDEXED_EXTENSIONS:
            files.append(path)
    logger.info(f"XSOAR repo: {len(files)} files collected from {xsoar_dir}")
    return files


def _load_file(path: Path) -> List[Document]:
    """Load a single file as LangChain Documents.

    For XSOAR YAML files, parses the structure and produces a clean
    human-readable summary instead of raw YAML.
    """
    try:
        # XSOAR YAML preprocessing — convert to readable text
        if path.suffix in (".yml", ".yaml"):
            summary = _summarize_xsoar_yaml(path)
            if summary:
                source = str(path)
                root = str(_project_root())
                if source.startswith(root):
                    source = source[len(root):].lstrip("/\\")
                return [Document(page_content=summary, metadata={"source": source})]

        loader = TextLoader(str(path), encoding="utf-8")
        docs = loader.load()
        # Normalise source metadata to a project-root-relative path
        root = str(_project_root())
        for doc in docs:
            src = doc.metadata.get("source", str(path))
            if src.startswith(root):
                doc.metadata["source"] = src[len(root):].lstrip("/\\")
        return docs
    except Exception as e:
        logger.warning(f"Failed to load {path}: {e}")
        return []


def _split_documents(documents: List[Document]) -> List[Document]:
    """Split documents using language-aware separators based on file extension."""
    py_splitter = RecursiveCharacterTextSplitter.from_language(
        language=Language.PYTHON,
        chunk_size=1200,
        chunk_overlap=200,
    )
    md_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1200,
        chunk_overlap=200,
        separators=["\n## ", "\n### ", "\n\n", "\n", " ", ""],
    )
    # YAML has no LangChain Language enum — use generic block-aware separators
    yml_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1200,
        chunk_overlap=200,
        separators=["\n\n", "\n", " ", ""],
    )

    chunks: List[Document] = []
    for doc in documents:
        source = doc.metadata.get("source", "")
        if source.endswith(".py"):
            splitter = py_splitter
        elif source.endswith((".yml", ".yaml")):
            splitter = yml_splitter
        else:
            splitter = md_splitter
        chunks.extend(splitter.split_documents([doc]))
    return chunks


def _run_rag_search(retriever, query: str, label: str) -> str:
    """Shared retrieval + formatting logic for both IR and XSOAR tools."""
    try:
        docs = retriever.invoke(query)
        if not docs:
            return f"No relevant {label} content found for: '{query}'"

        sources_content: dict = {}
        for doc in docs:
            source_file = doc.metadata.get("source", "unknown")
            sources_content.setdefault(source_file, []).append(doc.page_content.strip())

        parts = []
        for source_file, contents in sources_content.items():
            combined = "\n\n".join(contents[:3])
            parts.append(f"**{source_file}:**\n```\n{combined}\n```")

        result = "\n\n".join(parts[:8])
        source_list = list(sources_content.keys())
        result += f"\n\n**{'Sources' if len(source_list) > 1 else 'Source'}:** {', '.join(source_list)}"
        return result

    except Exception as e:
        logger.error(f"{label} search error: {e}")
        return f"Search failed: {e}"


def _doc_id(chunk: Document) -> str:
    content_hash = hashlib.md5(
        f"{chunk.metadata.get('source', '')}:{chunk.page_content}".encode()
    ).hexdigest()
    return content_hash


def _get_git_changes(repo_path: Path, since_days: int = 10) -> tuple:
    """Return (modified_or_added, deleted) paths relative to *repo_path*.

    Uses ``git log --name-status`` (newest-first) so the most-recent commit
    wins when a file appears in multiple commits within the window.
    """
    import subprocess
    result = subprocess.run(
        ["git", "log", f"--since={since_days} days ago",
         "--format=", "--name-status", "--no-merges"],
        cwd=str(repo_path), capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return [], []

    # First mention of a file reflects its latest state (git log is newest-first)
    file_status: dict = {}
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0][0]  # A, C, D, M, or R
        filepath = parts[-1]  # new name for renames
        if filepath not in file_status:
            file_status[filepath] = status
        # Track old name of renames as deleted
        if status == "R" and len(parts) >= 3 and parts[1] not in file_status:
            file_status[parts[1]] = "D"

    modified = [p for p, s in file_status.items() if s != "D"]
    deleted = [p for p, s in file_status.items() if s == "D"]
    return modified, deleted


def _is_curated_ir_file(rel_path: str) -> bool:
    """Return True if *rel_path* would be collected by ``_collect_ir_files``."""
    p = Path(rel_path)
    if p.suffix not in INDEXED_EXTENSIONS:
        return False
    if any(part in SKIP_DIRS for part in p.parts):
        return False
    if str(p) in CURATED_FILES:
        return True
    return any(str(p).startswith(d + "/") for d in CURATED_DIRS)


def _source_key(repo_path: Path, rel_path: str) -> str:
    """Compute the ChromaDB ``source`` metadata for a file, matching ``_load_file``."""
    full = str(repo_path / rel_path)
    ir_root = str(_project_root())
    if full.startswith(ir_root + "/"):
        return full[len(ir_root) + 1:]
    return full


class CodebaseIndexer:
    """Manages a the Windows triage agent ChromaDB index — either the IR codebase or the XSOAR repo.

    Args:
        chroma_path: Override path for the ChromaDB store.
        mode: ``"ir"`` indexes the IR source tree; ``"xsoar"`` indexes the XSOAR repo.
    """

    def __init__(self, chroma_path: Optional[str] = None, mode: str = "ir"):
        if mode not in ("ir", "xsoar"):
            raise ValueError(f"mode must be 'ir' or 'xsoar', got {mode!r}")
        self.mode = mode
        root = _project_root()
        self.chroma_path = chroma_path or str(root / "chroma_win_ai")
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        code_embed_model = os.environ.get("WINAI_EMBEDDING_MODEL")
        winai_base_url = os.environ.get("WINAI_EMBEDDING_BASE_URL")
        kwargs = {}
        if code_embed_model:
            kwargs["model"] = code_embed_model
        if winai_base_url:
            kwargs["base_url"] = winai_base_url
        self._embedding_fn = OllamaEmbeddingFunction(**kwargs)
        self.retriever = None

    @property
    def _collection_name(self) -> str:
        return XSOAR_COLLECTION_NAME if self.mode == "xsoar" else COLLECTION_NAME

    @property
    def client(self) -> chromadb.PersistentClient:
        if self._client is None:
            self._client = chromadb.PersistentClient(path=self.chroma_path)
        return self._client

    @property
    def collection(self):
        if self._collection is None:
            description = (
                "the Windows triage agent XSOAR automation YAML index"
                if self.mode == "xsoar"
                else "the Windows triage agent IR codebase source index"
            )
            self._collection = self.client.get_or_create_collection(
                name=self._collection_name,
                metadata={"description": description},
            )
        return self._collection

    def rebuild(self) -> bool:
        """Full rebuild: verify embeddings work, then delete + re-index.

        Pre-flight: embeds a test string before touching the existing collection.
        If the embedding server is unreachable the existing index is preserved.
        """
        try:
            label = "XSOAR" if self.mode == "xsoar" else "IR codebase"
            logger.info(f"the Windows triage agent {label} index: starting rebuild...")

            # Pre-flight: verify embedding server is reachable before we delete anything
            try:
                self._embedding_fn(["preflight check"])
                logger.info("Embedding server OK — proceeding with rebuild")
            except Exception as e:
                logger.error(f"Embedding server unreachable — aborting rebuild to preserve existing index: {e}")
                return False

            # Pull latest commits before indexing (XSOAR only)
            if self.mode == "xsoar":
                xsoar_path = os.environ.get("WINAI_XSOAR_REPO_PATH")
                if xsoar_path:
                    _pull_xsoar_repo(Path(xsoar_path))

            files = _collect_xsoar_files() if self.mode == "xsoar" else _collect_ir_files()
            logger.info(f"Collected {len(files)} source files to index")

            all_docs: List[Document] = []
            for f in files:
                all_docs.extend(_load_file(f))

            chunks = _split_documents(all_docs)
            logger.info(f"Split into {len(chunks)} chunks")

            if not chunks:
                logger.warning("No chunks produced — aborting to preserve existing index")
                return False

            # Only delete AFTER we have chunks and embeddings are verified
            try:
                self.client.delete_collection(self._collection_name)
                logger.info("Dropped existing collection")
            except Exception:
                pass
            self._collection = None  # Force re-create on next access

            # Embed and store in batches
            batch_size = 10
            stored = 0
            import time as _time
            _last_progress = _time.monotonic()
            for i in range(0, len(chunks), batch_size):
                batch = chunks[i: i + batch_size]
                texts = [c.page_content for c in batch]
                ids = [_doc_id(c) for c in batch]
                # Deduplicate within batch (ChromaDB rejects duplicate IDs)
                seen = set()
                unique_idx = [j for j, id_ in enumerate(ids) if id_ not in seen and not seen.add(id_)]
                if len(unique_idx) < len(batch):
                    batch = [batch[j] for j in unique_idx]
                    texts = [texts[j] for j in unique_idx]
                    ids = [ids[j] for j in unique_idx]
                metadatas = [c.metadata for c in batch]
                try:
                    embeddings = self._embedding_fn(texts)
                    self.collection.upsert(
                        ids=ids,
                        embeddings=embeddings,
                        documents=texts,
                        metadatas=metadatas,
                    )
                    stored += len(batch)
                    now = _time.monotonic()
                    if now - _last_progress >= 300:  # every 5 minutes
                        pct = stored * 100 // len(chunks)
                        logger.info(f"Rebuild progress: {stored}/{len(chunks)} chunks ({pct}%)")
                        _last_progress = now
                except Exception as e:
                    logger.error(f"Failed to embed batch {i}–{i + batch_size}: {e}")

            logger.info(f"the Windows triage agent {label} index rebuild complete: {stored} chunks stored")
            return stored > 0

        except Exception as e:
            logger.error(f"{label} index rebuild failed: {e}", exc_info=True)
            return False

    def incremental_update(self, since_days: int = 10) -> bool:
        """Re-index only files changed in git within the last *since_days* days.

        Two-phase approach: all embeddings are generated first; only after
        every batch succeeds are old chunks deleted and new ones upserted.
        Falls back to a full rebuild if the collection is empty.
        """
        label = "XSOAR" if self.mode == "xsoar" else "IR codebase"
        try:
            # Empty collection → fall back to full rebuild
            if self.collection.count() == 0:
                logger.info(f"the Windows triage agent {label} index is empty — falling back to full rebuild")
                return self.rebuild()

            # Pre-flight: verify embedding server before doing any work
            try:
                self._embedding_fn(["preflight check"])
            except Exception as e:
                logger.error(f"Embedding server unreachable — skipping update: {e}")
                return False

            # Determine repo path; pull latest for XSOAR
            if self.mode == "xsoar":
                xsoar_path = os.environ.get("WINAI_XSOAR_REPO_PATH")
                if not xsoar_path:
                    logger.warning("WINAI_XSOAR_REPO_PATH not set")
                    return False
                repo_path = Path(xsoar_path)
                _pull_xsoar_repo(repo_path)
            else:
                repo_path = _project_root()

            modified, deleted = _get_git_changes(repo_path, since_days)

            # Filter to indexable files
            if self.mode == "xsoar":
                exts = EXTERNAL_INDEXED_EXTENSIONS
                modified = [p for p in modified if Path(p).suffix in exts
                            and not any(part in SKIP_DIRS for part in Path(p).parts)]
                deleted = [p for p in deleted if Path(p).suffix in exts]
            else:
                modified = [p for p in modified if _is_curated_ir_file(p)]
                deleted = [p for p in deleted if _is_curated_ir_file(p)]

            if not modified and not deleted:
                logger.info(f"the Windows triage agent {label}: no indexed files changed in last {since_days} days")
                return True

            logger.info(f"the Windows triage agent {label} incremental update: "
                         f"{len(modified)} modified/added, {len(deleted)} deleted")

            # --- Phase 1: embed everything BEFORE any deletes ---
            prepared_batches: list = []
            if modified:
                all_docs: List[Document] = []
                for rel_path in modified:
                    full_path = repo_path / rel_path
                    if full_path.exists():
                        all_docs.extend(_load_file(full_path))
                chunks = _split_documents(all_docs)
                logger.info(f"Embedding {len(chunks)} chunks from {len(modified)} files")

                batch_size = 10
                import time as _time
                _last_progress = _time.monotonic()
                _embedded = 0
                for i in range(0, len(chunks), batch_size):
                    batch = chunks[i: i + batch_size]
                    texts = [c.page_content for c in batch]
                    ids = [_doc_id(c) for c in batch]
                    seen: set = set()
                    unique_idx = [j for j, id_ in enumerate(ids)
                                  if id_ not in seen and not seen.add(id_)]
                    if len(unique_idx) < len(batch):
                        batch = [batch[j] for j in unique_idx]
                        texts = [texts[j] for j in unique_idx]
                        ids = [ids[j] for j in unique_idx]
                    metadatas = [c.metadata for c in batch]
                    # Raises on failure → skips phase 2, preserving existing index
                    embeddings = self._embedding_fn(texts)
                    prepared_batches.append((ids, embeddings, texts, metadatas))
                    _embedded += len(batch)
                    now = _time.monotonic()
                    if now - _last_progress >= 300:  # every 5 minutes
                        pct = _embedded * 100 // len(chunks)
                        logger.info(f"Update progress: {_embedded}/{len(chunks)} chunks ({pct}%)")
                        _last_progress = now

            # --- Phase 2: delete old chunks, then upsert new ones ---
            for rel_path in set(modified + deleted):
                source = _source_key(repo_path, rel_path)
                try:
                    self.collection.delete(where={"source": source})
                except Exception as e:
                    logger.debug(f"Delete for {source}: {e}")

            stored = 0
            for ids, embeddings, texts, metadatas in prepared_batches:
                self.collection.upsert(
                    ids=ids, embeddings=embeddings,
                    documents=texts, metadatas=metadatas,
                )
                stored += len(ids)

            logger.info(f"the Windows triage agent {label} incremental update complete: "
                         f"{stored} chunks upserted, {len(deleted)} file(s) removed")
            return True

        except Exception as e:
            logger.error(f"{label} incremental update failed: {e}", exc_info=True)
            return False

    def initialize_retriever(self) -> bool:
        """Load the existing index and wire up a retriever. Returns False if empty."""
        label = "XSOAR" if self.mode == "xsoar" else "IR codebase"
        try:
            count = self.collection.count()
            if count == 0:
                logger.warning(f"the Windows triage agent {label} index is empty — run rebuild first")
                return False

            logger.info(f"the Windows triage agent {label} index loaded: {count} chunks")

            # Simple ChromaDB retriever (same pattern as DocumentProcessor)
            from my_bot.document.document_processor import ChromaRetriever
            self.retriever = ChromaRetriever(
                collection=self.collection,
                embedding_fn=self._embedding_fn,
                k=30,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to initialize codebase retriever: {e}")
            return False

    def create_rag_tool(self):
        """Return a LangChain tool that searches this index (IR or XSOAR)."""
        if not self.retriever:
            logger.error(f"{'XSOAR' if self.mode == 'xsoar' else 'IR'} retriever not initialized")
            return None

        from langchain_core.tools import tool

        retriever = self.retriever

        if self.mode == "xsoar":
            @tool
            def search_xsoar_code(query: str) -> str:
                """
                Searches the XSOAR automation repository for relevant YAML playbooks,
                scripts, and integrations. Use this for questions about how XSOAR
                automations work, how incidents are handled, or to find a specific
                playbook or integration by name or capability.
                Returns relevant YAML content with file attribution.
                """
                return _run_rag_search(retriever, query, "XSOAR")

            return search_xsoar_code
        else:
            @tool
            def search_ir_codebase(query: str) -> str:
                """
                Searches the IR (Incident Response) platform source files for relevant
                code, implementations, and feature explanations. Use this for any
                question about how a feature works, where something is implemented,
                or to show a code snippet from the IR codebase.
                Returns relevant source code with file attribution.
                """
                return _run_rag_search(retriever, query, "IR")

            return search_ir_codebase

    def get_stats(self) -> dict:
        try:
            return {"total_chunks": self.collection.count(), "chroma_path": self.chroma_path}
        except Exception:
            return {"total_chunks": 0, "chroma_path": self.chroma_path}


def rebuild_ir_index() -> bool:
    """Entry point for scheduler.py and manual runs — rebuilds IR codebase index."""
    return CodebaseIndexer(mode="ir").rebuild()


def rebuild_xsoar_index() -> bool:
    """Entry point for scheduler.py and manual runs — pulls + rebuilds XSOAR index."""
    return CodebaseIndexer(mode="xsoar").rebuild()


# Legacy alias so any existing callers still work
rebuild_win_ai_index = rebuild_ir_index


def update_ir_index(since_days: int = 10) -> bool:
    """Incremental update — re-indexes only files changed in git recently."""
    return CodebaseIndexer(mode="ir").incremental_update(since_days=since_days)


def update_xsoar_index(since_days: int = 10) -> bool:
    """Incremental update — pulls XSOAR repo + re-indexes only recent git changes."""
    return CodebaseIndexer(mode="xsoar").incremental_update(since_days=since_days)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = sys.argv[1:]
    mode = args[0] if args else "ir"
    action = args[1] if len(args) > 1 else "update"
    if mode not in ("ir", "xsoar") or action not in ("rebuild", "update"):
        print("Usage: python codebase_indexer.py [ir|xsoar] [rebuild|update]")
        exit(1)
    indexer = CodebaseIndexer(mode=mode)
    success = indexer.incremental_update() if action == "update" else indexer.rebuild()
    if success:
        stats = indexer.get_stats()
        print(f"{mode.upper()} index ready: {stats['total_chunks']} chunks at {stats['chroma_path']}")
    else:
        print(f"{mode.upper()} {action} failed — check logs")
        exit(1)
