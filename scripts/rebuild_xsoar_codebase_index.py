"""One-shot XSOAR index rebuild with clean YAML preprocessing."""
import sys, os, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

from dotenv import load_dotenv
load_dotenv("data/transient/.env")

from my_bot.document.codebase_indexer import CodebaseIndexer
indexer = CodebaseIndexer(mode="xsoar")
success = indexer.rebuild()
if success:
    stats = indexer.get_stats()
    print(f"XSOAR index rebuilt: {stats['total_chunks']} chunks at {stats['chroma_path']}")
else:
    print("XSOAR rebuild FAILED — check logs")
    sys.exit(1)
