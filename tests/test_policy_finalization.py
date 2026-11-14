"""Native interpreter links must stay inside the selected image."""
import ast
from pathlib import Path
import re
import tempfile
import unittest


class PolicyDependencyTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).parents[1]/'scripts/finalize-image.py'
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and
                        node.name == 'policy_compiler_dependencies')
        namespace = {'re': re}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        self.check = namespace['policy_compiler_dependencies']
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('usr/bin/router-policy-profile', 'usr/sbin/nft', 'usr/bin/python3.13'):
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic executable')
        self.python = self.root/'usr/bin/python3'

    def test_distribution_link_and_regular_interpreter_are_supported(self):
        self.python.symlink_to('python3.13')
        self.check(self.root)
        self.python.unlink()
        self.python.write_text('synthetic regular interpreter')
        self.check(self.root)

    def test_host_absolute_parent_and_unexpected_links_are_rejected(self):
        for target in ('/usr/bin/python3.13', '../bin/python3.13', '../../outside', 'other-python', '.'):
            with self.subTest(target=target):
                self.python.symlink_to(target)
                with self.assertRaises(ValueError):
                    self.check(self.root)
                self.python.unlink()

    def test_missing_or_indirect_interpreter_targets_are_rejected(self):
        self.python.symlink_to('python3.14')
        with self.assertRaises(ValueError):
            self.check(self.root)
        target = self.root/'usr/bin/python3.14'
        target.symlink_to('python3.13')
        with self.assertRaises(ValueError):
            self.check(self.root)
        target.unlink()
        target.mkdir()
        with self.assertRaises(ValueError):
            self.check(self.root)

    def test_other_compilers_cannot_be_replaced_with_links(self):
        self.python.symlink_to('python3.13')
        for name in ('usr/bin/router-policy-profile', 'usr/sbin/nft'):
            path = self.root/name
            path.unlink()
            path.symlink_to(self.root/'usr/bin/python3.13')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(self.root)
            path.unlink()
            path.write_text('synthetic executable')


if __name__ == '__main__':
    unittest.main()
