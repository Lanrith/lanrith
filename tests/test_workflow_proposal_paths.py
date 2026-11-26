"""Exercise the Git staging boundary for each supported repository layout."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from automation.common import MaintenanceError
from automation.control_updates import proposal_paths


class WorkflowProposalPathsTests(unittest.TestCase):
    def fixture(self, root, repo):
        files = {'.github/workflows/update.yml': 'name: Update\n',
                 'security/automation-update.json': '{}\n',
                 'security/slsa-assessment.json' if repo == 'Lanrith/lanrith'
                 else 'security/maintenance-source.json': '{}\n',
                 'security/unrelated.json': 'must stay unstaged\n',
                 'unrelated.txt': 'must stay unstaged\n'}
        for name, text in files.items():
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def test_each_repository_can_commit_its_complete_proposal_without_unrelated_files(self):
        for repo in ('Lanrith/lanrith', 'Lanrith/router-policy-agent', 'Lanrith/discovery-bridge'):
            with self.subTest(repo=repo), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root, repo)

                def git(*args):
                    return subprocess.run(['git', *args], cwd=root, check=True,
                                          capture_output=True, text=True).stdout

                git('init', '--quiet')
                old = subprocess.run(['git', 'add', '--', '.github/workflows/',
                    'security/maintenance-source.json', 'security/slsa-assessment.json',
                    'security/automation-update.json'], cwd=root, capture_output=True, text=True)
                self.assertNotEqual(old.returncode, 0)
                self.assertIn('did not match any files', old.stderr)
                git('add', '--', *proposal_paths(root, repo))
                git('-c', 'user.name=Proposal test', '-c', 'user.email=proposal@example.invalid',
                    '-c', 'commit.gpgsign=false', 'commit', '-m', 'Stage complete proposal')
                names = set(git('ls-tree', '-r', '--name-only', 'HEAD').splitlines())
                expected = {'.github/workflows/update.yml', 'security/automation-update.json',
                            'security/slsa-assessment.json' if repo == 'Lanrith/lanrith'
                            else 'security/maintenance-source.json'}
                self.assertEqual(names, expected)
                self.assertIn('?? security/unrelated.json', git('status', '--porcelain'))

    def test_required_evidence_cannot_be_silently_omitted(self):
        for repo, name in (('Lanrith/lanrith', 'security/slsa-assessment.json'),
                           ('Lanrith/router-policy-agent', 'security/maintenance-source.json'),
                           ('Lanrith/discovery-bridge', 'security/automation-update.json')):
            with self.subTest(repo=repo), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root, repo)
                (root/name).unlink()
                with self.assertRaisesRegex(MaintenanceError, 'missing required evidence'):
                    proposal_paths(root, repo)

    def test_symlinked_evidence_or_parent_is_rejected(self):
        for target in ('security/automation-update.json', 'security'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root, 'Lanrith/lanrith')
                path = root/target
                moved = root/'moved-evidence'
                path.rename(moved)
                path.symlink_to(moved, target_is_directory=moved.is_dir())
                with self.assertRaisesRegex(MaintenanceError, 'symlinks'):
                    proposal_paths(root, 'Lanrith/lanrith')

    def test_unknown_repository_is_rejected(self):
        with self.assertRaisesRegex(MaintenanceError, 'outside the maintenance installation'):
            proposal_paths(Path('/unused'), 'Lanrith/untrusted')
