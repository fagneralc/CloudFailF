import os
import sys
import importlib.util
import importlib.machinery
import py_compile
import marshal

class CacheHandler:
    def __init__(self, cache_dir=".cache"):
        self.project_root = self._find_project_root()
        self.cache_dir = os.path.join(self.project_root, cache_dir)
        os.makedirs(self.cache_dir, exist_ok=True)

    def _find_project_root(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        while current_dir != os.path.dirname(current_dir):
            if os.path.exists(os.path.join(current_dir, 'cloudfail.py')):
                return current_dir
            current_dir = os.path.dirname(current_dir)
        return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def _is_project_file(self, path):
        abs_path = os.path.abspath(path)
        return abs_path.startswith(self.project_root) and '/lib/' in abs_path

    def _create_import_hook(self):
        cache_dir = self.cache_dir
        project_root = self.project_root

        class CustomLoader(importlib.machinery.SourceFileLoader):
            def get_code(self, fullname):
                source_path = self.get_filename(fullname)
                
                if not source_path.endswith(".py") or not self._is_project_file(source_path):
                    return super().get_code(fullname)

                rel_path = os.path.relpath(source_path, project_root)
                cache_path = os.path.join(cache_dir, rel_path + "c")
                
                if not os.path.exists(cache_path) or os.path.getmtime(source_path) > os.path.getmtime(cache_path):
                    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                    py_compile.compile(source_path, cfile=cache_path)

                with open(cache_path, "rb") as f:
                    data = f.read()
                    return marshal.loads(data[16:])

            def get_filename(self, fullname):
                return super().get_filename(fullname)
                
            def _is_project_file(self, path):
                abs_path = os.path.abspath(path)
                return abs_path.startswith(project_root) and '/lib/' in abs_path

        class CustomFinder(importlib.machinery.PathFinder):
            @classmethod
            def find_spec(cls, fullname, path=None, target=None):
                spec = super().find_spec(fullname, path, target)
                if spec and isinstance(spec.loader, importlib.machinery.SourceFileLoader):
                    spec.loader = CustomLoader(spec.loader.name, spec.loader.path)
                return spec

        return CustomFinder

    def setup_import_hook(self):
        sys.meta_path.insert(0, self._create_import_hook())