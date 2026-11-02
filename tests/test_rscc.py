import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import types
import contextlib
import io

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/rscc.py'
sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPT.parent))


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.target = self.root / 'modules/orders'
        self.target.mkdir(parents=True)
        (self.target / '.hidden.php').write_text('<?php return 1;')
        (self.target / 'controller.custom').write_text('<?php echo $_GET["x"];')
        (self.target / 'README.md').write_text('Module documentation')
        (self.target / '.gitignore').write_text('generated/\n')
        (self.target / 'generated').mkdir()
        (self.target / 'generated/code.php').write_text('<?php return 2;')
        self.module = self.root / 'rscc/orders'

    def tearDown(self):
        self.temp.cleanup()

    def call(self, *args, code=0):
        result = subprocess.run([sys.executable, str(SCRIPT), *map(str,args)], capture_output=True, text=True)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def read(self, filename):
        return json.loads(Path(filename).read_text())

    def save(self, filename, value):
        Path(filename).write_text(json.dumps(value))

    def prepare(self):
        self.call('inventory', '--root', self.root, '--target', self.target)
        rows = self.read(self.module / 'file_notes.json')
        for row in rows:
            row.update(source_related=not row['path'].endswith(('.md', '.gitignore')), inspected=True,
                       purpose='Purpose from fixture inspection', behavior='Observed behavior from fixture inspection', relationships='No external dependency')
        self.save(self.module / 'file_notes.json', rows)
        self.call('structure', '--module-dir', self.module)
        self.run = Path(self.call('start', '--module-dir', self.module, '--utc-offset', '+07:00').stdout.strip())
        review = self.read(self.run / 'review.json')
        for row, note in zip(review['files'], rows):
            row.update(read_complete=True, status='NEEDS VERIFICATION' if note['source_related'] else 'NOT APPLICABLE', notes='Host runtime unavailable' if note['source_related'] else 'Passive documentation/configuration metadata')
            if note['source_related']:
                row['checks'] = [dict(standard='ASVS', reference='Topic: host protection, exact reference unverified', status='NEEDS VERIFICATION', evidence='Source fully read; missing host context prevents verification')]
        self.save(self.run / 'review.json', review)
        (self.run / 'standards.md').write_text('Standards verification unavailable in deterministic bookkeeping test.')
        (self.run / 'review-summary.md').write_text('Source fixture review. Catalog verification not performed in this helper test.')

    def prepare_files(self, paths=None):
        paths = paths or [self.target / '.hidden.php']
        arguments = ['files', '--root', self.root, '--utc-offset', '+07:00']
        for path in paths:
            arguments.extend(['--file', path])
        self.run = Path(self.call(*arguments).stdout.strip())
        review = self.read(self.run / 'review.json')
        for row in review['files']:
            row.update(read_complete=True, status='NEEDS VERIFICATION', notes='Selected source fully read; host context not selected.')
            row['checks'] = [dict(standard='ASVS', reference='Host protection topic; exact reference unverified', status='NEEDS VERIFICATION', evidence='Selected file read; external host dependencies not selected.')]
        self.save(self.run / 'review.json', review)
        (self.run / 'standards.md').write_text('Standards are not fetched in deterministic helper tests.')
        (self.run / 'review-summary.md').write_text('Only selected files were assessed; external host evidence remains unavailable.')

    def test_inventory_includes_hidden_and_unknown_extensions_but_applies_gitignore(self):
        self.call('inventory', '--root', self.root, '--target', self.target)
        entries = self.read(self.module / 'inventory.json')['entries']
        self.assertEqual({r['path'] for r in entries}, {'.hidden.php', 'controller.custom', 'README.md', '.gitignore'})
        self.assertTrue(all(len(r['sha256']) == 64 for r in entries))

    def test_structure_requires_every_file(self):
        self.call('inventory', '--root', self.root, '--target', self.target)
        rows = self.read(self.module / 'file_notes.json')
        self.save(self.module / 'file_notes.json', rows[:-1])
        result = self.call('structure', '--module-dir', self.module, code=1)
        self.assertIn('coverage mismatch', result.stderr)

    def test_start_rejects_stale_structure(self):
        self.prepare()
        (self.target / 'new.php').write_text('<?php echo 1;')
        result = self.call('start', '--module-dir', self.module, '--utc-offset', '+07:00', code=1)
        self.assertIn('drift', result.stderr)

    def test_complete_reading_is_distinct_from_verified_controls(self):
        self.prepare()
        self.call('finish', '--run-dir', self.run)
        self.assertIn('**COMPLETE**', (self.run / 'coverage.md').read_text())
        self.assertIn('NEEDS VERIFICATION', (self.run / 'file-review.md').read_text())

    def test_missing_and_duplicate_ledger_rows_rejected(self):
        self.prepare()
        original = self.read(self.run / 'review.json')
        original['files'].append(dict(original['files'][0]))
        self.save(self.run / 'review.json', original)
        self.assertIn('Duplicate paths', self.call('finish', '--run-dir', self.run, code=1).stderr)
        original['files'] = original['files'][1:-1]
        self.save(self.run / 'review.json', original)
        self.assertIn('coverage mismatch', self.call('finish', '--run-dir', self.run, code=1).stderr)

    def test_drift_creates_incomplete_reports(self):
        self.prepare()
        (self.target / '.hidden.php').write_text('<?php return 9;')
        self.call('finish', '--run-dir', self.run, code=2)
        self.assertIn('**INCOMPLETE**', (self.run / 'coverage.md').read_text())

    def test_repeat_inventory_resets_review_and_preserves_runs(self):
        self.prepare()
        old_id = self.read(self.run / 'inventory.json')['scan_id']
        self.call('inventory', '--root', self.root, '--target', self.target)
        self.assertNotEqual(old_id, self.read(self.module / 'inventory.json')['scan_id'])
        self.assertTrue(self.run.is_dir())
        self.assertTrue(all(r['inspected'] is False for r in self.read(self.module / 'file_notes.json')))

    def test_output_is_not_recursively_inventoried(self):
        self.call('inventory', '--root', self.root, '--target', self.root, '--allow-project-root')
        parent_module = self.root / 'rscc' / self.root.name
        self.call('inventory', '--root', self.root, '--target', self.root, '--allow-project-root')
        self.assertFalse(any(r['path'].startswith('rscc/') for r in self.read(parent_module / 'inventory.json')['entries']))

    def test_minute_collision_does_not_overwrite(self):
        self.prepare()
        original = (self.run / 'review.json').read_bytes()
        self.call('start', '--module-dir', self.module, '--utc-offset', '+07:00', code=1)
        self.assertEqual(original, (self.run / 'review.json').read_bytes())

    def test_basename_collision_and_approved_alias(self):
        self.call('inventory', '--root', self.root, '--target', self.target)
        other = self.root / 'other/orders'
        other.mkdir(parents=True)
        self.call('inventory', '--root', self.root, '--target', other, code=1)
        self.call('inventory', '--root', self.root, '--target', other, '--output-name', 'other-orders')
        self.assertEqual(self.read(self.root / 'rscc/other-orders/inventory.json')['target'], str(other.resolve()))

    def test_findings_require_reciprocal_file_links(self):
        self.prepare()
        review = self.read(self.run / 'review.json')
        source_row = next(r for r in review['files'] if r['path'] == 'controller.custom')
        finding = dict(id='RSCC-001', category='security', severity='High', title='Unsafe output',
                       description='Request input reaches output without encoding.', impact='Script execution.',
                       remediation='Apply contextual output encoding.', confidence='High', verification='Source trace.',
                       locations=[dict(path='controller.custom', lines='1', evidence='Request parameter echoed directly.')],
                       standard_refs=['CWE-79'], acceptance_criteria=['HTML characters are encoded in output.'])
        finding['identity'] = dict(path='controller.custom', symbol='<file>', mechanism='unencoded-html-output')
        finding['severity_assessment'] = dict(policy='rscc-severity-v1', kind='security', impact='sensitive', reachability='authenticated', context_id='source-only', basis='Fixture declares a confirmed cross-user sensitive effect accessible by an authenticated user.')
        review['findings'] = [finding]
        self.save(self.run / 'review.json', review)
        result = self.call('finish', '--run-dir', self.run, code=1)
        self.assertIn('missing from affected file', result.stderr)
        source_row.update(status='FAIL', finding_ids=['RSCC-001'])
        source_row['checks'][0].update(status='FAIL', evidence='Request parameter echoed directly on line 1.')
        self.save(self.run / 'review.json', review)
        self.call('finish', '--run-dir', self.run)
        self.assertIn('RSCC-001', (self.run / 'findings.md').read_text())

    def test_partial_read_cannot_pass(self):
        self.prepare()
        review = self.read(self.run / 'review.json')
        row = next(r for r in review['files'] if r['path'] == 'controller.custom')
        row.update(status='PASS', read_complete=False)
        row['checks'][0]['status'] = 'PASS'
        self.save(self.run / 'review.json', review)
        self.assertIn('before full reading', self.call('finish', '--run-dir', self.run, code=1).stderr)

    def add_excluded_directories(self):
        for relative in ('vendor', 'node_modules', 'src/build', 'src/deeper/vendor', 'src/deeper/node_modules', '.git', 'src/.github', 'src/deeper/.gitlab', '.gitea'):
            directory = self.target / relative
            directory.mkdir(parents=True)
            (directory / 'excluded.php').write_text('<?php excluded();')

    def test_excluded_directories_are_pruned_before_reading(self):
        self.add_excluded_directories()
        module = types.ModuleType('rscc_under_test')
        exec(compile(SCRIPT.read_text(encoding='utf-8'), str(SCRIPT), 'exec'), module.__dict__)
        original_iterdir = Path.iterdir
        def guarded_iterdir(folder):
            self.assertNotIn(folder.name, module.EXCLUDED_DIRECTORY_NAMES, 'Excluded directory was enumerated')
            return original_iterdir(folder)
        excluded = []
        with patch.object(Path, 'iterdir', guarded_iterdir):
            entries = module.snapshot(self.root, self.target, excluded=excluded)
        self.assertEqual(len(entries), 4)
        self.assertEqual(len(excluded), 10)
        self.assertTrue(all('excluded.php' not in row['path'] for row in entries))

    def test_similar_names_and_manifests_remain_in_scope(self):
        self.add_excluded_directories()
        for relative in ('vendor-tools/custom.php', 'build-tools/build.php', 'app/code/Vendor/Module.php'):
            path = self.target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('<?php return 1;')
        # Ordinary files called build and a lockfile must not be pruned.
        (self.target / 'build').write_text('Build instructions')
        (self.target / 'composer.lock').write_text('{"packages": []}')
        self.call('inventory', '--root', self.root, '--target', self.target)
        inv = self.read(self.module / 'inventory.json')
        included = {row['path'] for row in inv['entries']}
        self.assertTrue({'vendor-tools/custom.php', 'build-tools/build.php', 'app/code/Vendor/Module.php', 'build', 'composer.lock'} <= included)
        self.assertEqual(inv['excluded_directory_names'], ['vendor', 'node_modules', 'build', '.git', '.github', '.gitlab', '.gitea'])

    def test_exclusions_are_reported_without_blocking_scoped_coverage(self):
        self.add_excluded_directories()
        self.prepare()
        (self.target / 'vendor/excluded.php').write_text('<?php changed();')
        self.call('finish', '--run-dir', self.run)
        for path in (self.module / 'structure_file.md', self.run / 'coverage.md'):
            document = path.read_text()
            self.assertIn('vendor/', document)
            self.assertIn('node_modules/', document)
            self.assertIn('build/', document)
            for name in ('.git/', '.github/', '.gitlab/', '.gitea/'):
                self.assertIn(name, document)
            self.assertIn('not PASS', document)
        self.assertIn('**COMPLETE**', (self.run / 'coverage.md').read_text())
        self.assertNotIn('excluded.php', (self.run / 'file-review.md').read_text())

    def test_excluded_target_is_rejected(self):
        for name in ('vendor', '.git', '.github', '.gitlab', '.gitea'):
            with self.subTest(directory=name):
                directory = self.target / name / 'library'
                directory.mkdir(parents=True)
                result = self.call('inventory', '--root', self.root, '--target', directory, code=1)
                self.assertIn('excluded', result.stderr)

    def test_git_related_files_and_similar_directories_remain_in_scope(self):
        for name in ('.gitattributes', '.gitmodules', '.git'):
            (self.target / name).write_text('Git configuration metadata')
        directory = self.target / '.github-tools'
        directory.mkdir()
        (directory / 'tool.php').write_text('<?php return 1;')
        self.call('inventory', '--root', self.root, '--target', self.target)
        paths = {row['path'] for row in self.read(self.module / 'inventory.json')['entries']}
        self.assertTrue({'.gitignore', '.gitattributes', '.gitmodules', '.git', '.github-tools/tool.php'} <= paths)

    def test_historical_snapshot_keeps_recorded_scope(self):
        self.prepare()
        inv = self.read(self.run / 'inventory.json')
        inv.pop('excluded_directory_names')
        self.save(self.run / 'inventory.json', inv)
        directory = self.target / 'vendor'
        directory.mkdir()
        (directory / 'new.php').write_text('<?php legacy_scope_change();')
        self.call('finish', '--run-dir', self.run, code=2)
        self.assertIn('**INCOMPLETE**', (self.run / 'coverage.md').read_text())

    def test_accidental_project_root_target_is_rejected_before_writes(self):
        result = self.call('inventory', '--root', self.root, '--target', self.root, code=1)
        self.assertIn('explicitly selected', result.stderr)
        self.assertFalse((self.root / 'rscc').exists())

    def test_only_selected_target_is_enumerated_and_mapped(self):
        (self.root / 'outside.php').write_text('<?php OUTSIDE_ROOT_FILE();')
        sibling = self.root / 'modules/orders-other'
        sibling.mkdir()
        (sibling / 'sibling.php').write_text('<?php OUTSIDE_SIBLING();')
        module = types.ModuleType('rscc_scope_test')
        exec(compile(SCRIPT.read_text(encoding='utf-8'), str(SCRIPT), 'exec'), module.__dict__)
        original_iterdir = Path.iterdir
        def guarded_iterdir(folder):
            self.assertTrue(folder.is_relative_to(self.target), f'Enumerated outside selected target: {folder}')
            return original_iterdir(folder)
        with patch.object(Path, 'iterdir', guarded_iterdir):
            entries = module.snapshot(self.root, self.target)
        self.assertEqual(len(entries), 4)
        self.prepare()
        inv = self.read(self.module / 'inventory.json')
        self.assertEqual(inv['target'], str(self.target.resolve()))
        document = (self.module / 'structure_file.md').read_text()
        self.assertNotIn('outside.php', document)
        self.assertNotIn('sibling.php', document)
        self.assertEqual(self.module / 'structure_file.md', self.root / 'rscc/orders/structure_file.md')

    def test_missing_target_never_falls_back_to_project_root(self):
        self.call('inventory', '--root', self.root, '--target', self.target / 'missing', code=1)
        self.assertFalse((self.root / 'rscc').exists())

    def test_structure_revalidates_recorded_target_before_rebuilding_map(self):
        self.prepare()
        original = (self.module / 'structure_file.md').read_bytes()
        inv = self.read(self.module / 'inventory.json')
        inv['target'] = str(self.root.resolve())
        self.save(self.module / 'inventory.json', inv)
        result = self.call('structure', '--module-dir', self.module, code=1)
        self.assertIn('explicitly selected', result.stderr)
        self.assertEqual(original, (self.module / 'structure_file.md').read_bytes())

    def test_single_file_mode_finishes_without_structure_documents(self):
        self.prepare_files()
        self.assertEqual(self.run.parent, self.root / 'rscc/file-reviews')
        self.call('finish', '--run-dir', self.run)
        self.assertEqual({p.name for p in self.run.iterdir()}, {'inventory.json', 'review.json', 'standards.md', 'review-summary.md', 'file-review.md', 'findings.md', 'coverage.md'})
        self.assertIn('**COMPLETE**', (self.run / 'coverage.md').read_text())
        self.assertEqual(self.read(self.run / 'inventory.json')['mode'], 'files')

    def test_file_list_contains_only_requested_files_and_deduplicates(self):
        selected = [self.target / '.hidden.php', self.target / 'controller.custom', self.target / 'generated/code.php']
        self.prepare_files([*selected, selected[0]])
        inv = self.read(self.run / 'inventory.json')
        self.assertEqual(len(inv['selected_files']), 3)
        self.assertEqual({r['path'] for r in inv['entries']}, {p.relative_to(self.root).as_posix() for p in selected})
        self.call('finish', '--run-dir', self.run)
        self.assertNotIn('README.md', (self.run / 'file-review.md').read_text())

    def test_file_mode_never_enumerates_a_source_directory(self):
        module = types.ModuleType('rscc_file_scope_test')
        exec(compile(SCRIPT.read_text(encoding='utf-8'), str(SCRIPT), 'exec'), module.__dict__)
        selected = self.target / '.hidden.php'
        arguments = types.SimpleNamespace(root=str(self.root), file=[str(selected)], utc_offset='+07:00')
        with patch.object(Path, 'iterdir', side_effect=AssertionError('Directory enumeration is forbidden')), patch.object(module, 'sha_file', wraps=module.sha_file) as hashes, contextlib.redirect_stdout(io.StringIO()):
            module.files_mode(arguments)
        self.assertEqual([call.args[0] for call in hashes.call_args_list], [selected])

    def test_file_mode_preserves_existing_folder_structure(self):
        self.prepare()
        before = {name: (self.module / name).read_bytes() for name in ('inventory.json', 'file_notes.json', 'structure_file.md')}
        self.prepare_files()
        self.call('finish', '--run-dir', self.run)
        for name, content in before.items():
            self.assertEqual((self.module / name).read_bytes(), content)

    def test_same_named_files_in_different_folders_remain_distinct(self):
        other = self.root / 'other/.hidden.php'
        other.parent.mkdir()
        other.write_text('<?php return 3;')
        self.prepare_files([self.target / '.hidden.php', other])
        self.call('finish', '--run-dir', self.run)
        report = (self.run / 'file-review.md').read_text()
        self.assertIn('modules/orders/.hidden.php', report)
        self.assertIn('other/.hidden.php', report)

    def test_file_mode_rejects_invalid_paths_without_creating_reports(self):
        excluded = self.target / 'vendor/library.php'
        excluded.parent.mkdir()
        excluded.write_text('<?php return 1;')
        for path in (self.target / 'missing.php', self.target, excluded):
            with self.subTest(path=path):
                self.call('files', '--root', self.root, '--file', self.target / '.hidden.php', '--file', path, '--utc-offset', '+07:00', code=1)
                self.assertFalse((self.root / 'rscc').exists())

    def test_file_mode_ignores_neighbor_changes(self):
        self.prepare_files()
        (self.target / 'controller.custom').write_text('<?php unrelated_change();')
        (self.target / 'new.php').write_text('<?php unrelated_new_file();')
        self.call('finish', '--run-dir', self.run)
        self.assertIn('**COMPLETE**', (self.run / 'coverage.md').read_text())

    def test_file_mode_detects_selected_file_drift_and_deletion(self):
        self.prepare_files()
        selected = self.target / '.hidden.php'
        selected.write_text('<?php changed();')
        self.call('finish', '--run-dir', self.run, code=2)
        self.assertIn('**INCOMPLETE**', (self.run / 'coverage.md').read_text())
        selected.unlink()
        self.call('finish', '--run-dir', self.run, code=2)

    def test_file_mode_requires_every_selected_ledger_entry(self):
        self.prepare_files([self.target / '.hidden.php', self.target / 'controller.custom'])
        review = self.read(self.run / 'review.json')
        review['files'].pop()
        self.save(self.run / 'review.json', review)
        self.assertIn('coverage mismatch', self.call('finish', '--run-dir', self.run, code=1).stderr)

    def test_file_mode_collision_does_not_overwrite_existing_run(self):
        self.prepare_files()
        original = (self.run / 'review.json').read_bytes()
        self.call('files', '--root', self.root, '--file', self.target / 'controller.custom', '--utc-offset', '+07:00', code=1)
        self.assertEqual(original, (self.run / 'review.json').read_bytes())

    def test_gitignore_patterns_negation_and_report_provenance(self):
        (self.target / '.gitignore').write_text('generated/\n*.log\n!keep.log\n/root-only.php\n**/secret?.php\n\\#notes.php\n\\!bang.php\n')
        for relative in ('drop.log', 'keep.log', 'root-only.php', 'sub/root-only.php', 'sub/secret1.php', '#notes.php', '!bang.php'):
            path = self.target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('<?php fixture();')
        self.prepare()
        inv = self.read(self.module / 'inventory.json')
        paths = {row['path'] for row in inv['entries']}
        self.assertTrue({'keep.log', 'sub/root-only.php'} <= paths)
        self.assertFalse({'drop.log', 'root-only.php', 'sub/secret1.php', '#notes.php', '!bang.php'} & paths)
        self.assertTrue(inv['gitignore_enabled'])
        self.assertEqual(inv['gitignore_files'][0]['path'], '.gitignore')
        doc = (self.module / 'structure_file.md').read_text()
        self.assertIn('Local .gitignore rules', doc)
        self.assertIn('!keep.log', doc)
        self.assertIn('.gitignore:2 (*.log)', doc)
        self.call('finish', '--run-dir', self.run)
        self.assertIn('Local .gitignore rules', (self.run / 'coverage.md').read_text())

    def test_nested_gitignore_overrides_only_its_subtree(self):
        (self.target / '.gitignore').write_text('generated/\n*.tmp\n')
        sub = self.target / 'sub'
        sub.mkdir()
        (sub / '.gitignore').write_text('!keep.tmp\nprivate.php\n')
        for relative in ('keep.tmp', 'sub/keep.tmp', 'sub/drop.tmp', 'sub/private.php', 'private.php'):
            (self.target / relative).write_text('<?php fixture();')
        self.call('inventory', '--root', self.root, '--target', self.target)
        inv = self.read(self.module / 'inventory.json')
        paths = {row['path'] for row in inv['entries']}
        self.assertTrue({'sub/keep.tmp', 'private.php'} <= paths)
        self.assertFalse({'keep.tmp', 'sub/drop.tmp', 'sub/private.php'} & paths)
        self.assertEqual({r['path'] for r in inv['gitignore_files']}, {'.gitignore', 'sub/.gitignore'})

    def test_ignored_directory_is_not_traversed_or_hashed(self):
        (self.target / '.gitignore').write_text('generated/\ncache/\n')
        cache = self.target / 'cache'
        cache.mkdir()
        (cache / '.gitignore').write_text('!must-not-be-read.php\n')
        (cache / 'must-not-be-read.php').write_text('<?php ignored();')
        module = types.ModuleType('rscc_ignore_pruning')
        exec(compile(SCRIPT.read_text(encoding='utf-8'), str(SCRIPT), 'exec'), module.__dict__)
        original_iterdir, original_sha = Path.iterdir, module.sha_file
        def guarded_iterdir(folder):
            self.assertNotIn(folder.name, {'cache', 'generated'})
            return original_iterdir(folder)
        def guarded_sha(path):
            self.assertFalse(path.is_relative_to(cache) or path.is_relative_to(self.target / 'generated'))
            return original_sha(path)
        with patch.object(Path, 'iterdir', guarded_iterdir), patch.object(module, 'sha_file', guarded_sha):
            records = []
            module.snapshot(self.root, self.target, gitignore_files=records)
        self.assertEqual([r['path'] for r in records], ['.gitignore'])

    def test_parent_gitignore_is_not_read_or_applied(self):
        parent_ignore = self.root / '.gitignore'
        parent_ignore.write_text('*.php\ncontroller.custom\n')
        original_read = Path.read_bytes
        def guarded_read(path):
            self.assertNotEqual(path, parent_ignore)
            return original_read(path)
        module = types.ModuleType('rscc_ignore_boundary')
        exec(compile(SCRIPT.read_text(encoding='utf-8'), str(SCRIPT), 'exec'), module.__dict__)
        with patch.object(Path, 'read_bytes', guarded_read):
            entries = module.snapshot(self.root, self.target)
        self.assertTrue({'.hidden.php', 'controller.custom'} <= {r['path'] for r in entries})

    def test_ignore_metadata_changes_invalidate_scope_even_when_self_ignored(self):
        (self.target / '.gitignore').write_text('.gitignore\ngenerated/\n')
        self.prepare()
        self.assertNotIn('.gitignore', {r['path'] for r in self.read(self.module / 'inventory.json')['entries']})
        (self.target / '.gitignore').write_text('.gitignore\ngenerated/\n# updated scope metadata\n')
        self.call('finish', '--run-dir', self.run, code=2)
        self.assertIn('**INCOMPLETE**', (self.run / 'coverage.md').read_text())

    def test_fixed_exclusions_cannot_be_reincluded_by_gitignore(self):
        self.add_excluded_directories()
        (self.target / '.gitignore').write_text('!vendor/\n!node_modules/\n!build/\n!.github/\n')
        self.call('inventory', '--root', self.root, '--target', self.target)
        paths = {r['path'] for r in self.read(self.module / 'inventory.json')['entries']}
        self.assertFalse(any('excluded.php' in p for p in paths))

    def test_git_is_required_only_when_folder_ignore_file_exists(self):
        module = types.ModuleType('rscc_missing_git')
        exec(compile(SCRIPT.read_text(encoding='utf-8'), str(SCRIPT), 'exec'), module.__dict__)
        with patch.object(module.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'Git CLI is required'):
                module.snapshot(self.root, self.target)
            (self.target / '.gitignore').unlink()
            self.assertEqual(len(module.snapshot(self.root, self.target)), 4)

    def test_ignore_rules_are_refreshed_on_every_folder_inventory(self):
        self.call('inventory', '--root', self.root, '--target', self.target)
        (self.target / '.gitignore').write_text('generated/\ncontroller.custom\n')
        self.call('inventory', '--root', self.root, '--target', self.target)
        inv = self.read(self.module / 'inventory.json')
        self.assertNotIn('controller.custom', {r['path'] for r in inv['entries']})
        self.assertTrue(any(r['pattern'] == 'controller.custom' for r in inv['gitignore_exclusions']))

    def test_directory_only_gitignore_pattern_does_not_hide_git_pointer_file(self):
        (self.target / '.gitignore').write_text('.git/\ngenerated/\n')
        (self.target / '.git').write_text('gitdir: /unselected-metadata\n')
        self.call('inventory', '--root', self.root, '--target', self.target)
        self.assertIn('.git', {r['path'] for r in self.read(self.module / 'inventory.json')['entries']})

    def functional_finding(self, severity='Medium', path=None):
        review = self.read(self.run / 'review.json')
        row = next(r for r in review['files'] if r['path'] == path) if path else review['files'][0]
        row.update(status='FAIL', finding_ids=['RSCC-001'])
        row['checks'][0].update(status='FAIL', evidence='Fixture represents a source-confirmed blocked auxiliary admin action.')
        finding = dict(id='RSCC-001', category='bug', severity=severity, title='Admin capture/cancel/refund action fails',
                       description='Missing class resolution prevents the administrative action.', impact='The auxiliary admin action is blocked.',
                       remediation='Resolve the intended class explicitly.', confidence='High', verification='Source-confirmed fixture.',
                       locations=[dict(path=row['path'], lines='1', evidence='Unresolved WC_Order reference in an admin action.')],
                       standard_refs=['Functional correctness; no CVSS score assigned'], acceptance_criteria=['Administrative actions resolve WC_Order and reach the expected handler.'],
                       identity=dict(path=row['path'], symbol='Demo\\Admin\\Ajax', mechanism='unresolved-class:WC_Order'),
                       severity_assessment=dict(policy='rscc-severity-v1', kind='functional', impact='auxiliary-blocked', context_id='source-only', basis='Only an auxiliary admin action is proven blocked; no core checkout outage or permanent loss established.'))
        review['findings'] = [finding]
        self.save(self.run / 'review.json', review)
        return review

    def test_medium_auxiliary_bug_cannot_be_freely_labeled_high(self):
        self.prepare_files()
        self.functional_finding('High')
        result = self.call('finish', '--run-dir', self.run, code=1)
        self.assertIn('expected Medium', result.stderr)

    def test_functional_matrix_is_independent_of_wording_confidence_and_order(self):
        from severity import assess, FUNCTIONAL
        for impact, expected in FUNCTIONAL.items():
            for confidence in ('Low', 'Medium', 'High'):
                for index in range(10):
                    finding = dict(id=f'RSCC-{index:03}', category='bug', confidence=confidence, title=f'Different description {index}', severity_assessment=dict(policy='rscc-severity-v1', kind='functional', impact=impact, context_id='source-only', basis='Fixture supplies the stated consequence class.'))
                    assess(finding)
                    self.assertEqual(finding['severity'], expected)

    def test_security_matrix_and_advisory_rules_are_deterministic(self):
        from severity import assess, SECURITY
        for impact, reachability_levels in SECURITY.items():
            for reachability, expected in reachability_levels.items():
                finding = dict(id='RSCC-001', category='security', severity_assessment=dict(policy='rscc-severity-v1', kind='security', impact=impact, reachability=reachability, context_id='source-only', basis='Fixture supplies established impact and the least-privileged established actor.'))
                assess(finding)
                self.assertEqual(finding['severity'], expected)
        for category in ('verification-gap', 'improve'):
            finding = dict(id='RSCC-001', category=category, confidence='High', severity_assessment=dict(policy='rscc-severity-v1', kind='advisory', impact='none', context_id='source-only', basis='No confirmed impact; verify missing context.'))
            assess(finding)
            self.assertEqual(finding['severity'], 'Informational')

    def test_helper_calculates_missing_severity_and_records_policy(self):
        self.prepare_files()
        review = self.functional_finding()
        review['findings'][0].pop('severity')
        self.save(self.run / 'review.json', review)
        self.call('finish', '--run-dir', self.run)
        saved = self.read(self.run / 'review.json')
        self.assertEqual(saved['findings'][0]['severity'], 'Medium')
        self.assertEqual(saved['severity_policy'], 'rscc-severity-v1')
        self.assertEqual(len(saved['findings'][0]['stable_key']), 64)
        self.assertIn('Severity assessment:', (self.run / 'findings.md').read_text())

    def test_stable_identity_ignores_id_title_line_number_changes(self):
        self.prepare_files()
        self.functional_finding()
        self.call('finish', '--run-dir', self.run)
        review = self.read(self.run / 'review.json')
        original_key = review['findings'][0]['stable_key']
        finding = review['findings'][0]
        finding.update(id='RSCC-010', title='Different wording for the same unresolved class', confidence='Medium')
        finding['locations'][0]['lines'] = '1-2'
        review['files'][0]['finding_ids'] = ['RSCC-010']
        self.save(self.run / 'review.json', review)
        self.call('finish', '--run-dir', self.run)
        saved = self.read(self.run / 'review.json')
        self.assertEqual(saved['findings'][0]['stable_key'], original_key)
        self.assertEqual(saved['findings'][0]['severity'], 'Medium')
        self.assertEqual(self.read(self.root / 'rscc/severity_registry.json')['history'], [])

    def test_registry_blocks_silent_reclassification_with_unchanged_code(self):
        self.prepare_files()
        self.functional_finding()
        self.call('finish', '--run-dir', self.run)
        registry = self.root / 'rscc/severity_registry.json'
        previous = registry.read_bytes()
        review = self.read(self.run / 'review.json')
        review['findings'][0]['severity_assessment']['impact'] = 'core-blocked'
        review['findings'][0]['severity'] = 'High'
        self.save(self.run / 'review.json', review)
        self.assertIn('changed without', self.call('finish', '--run-dir', self.run, code=1).stderr)
        self.assertEqual(registry.read_bytes(), previous)
        self.assertFalse((self.root / 'rscc/severity_registry.lock').exists())

    def test_supported_context_change_is_audited(self):
        self.prepare_files()
        self.functional_finding()
        self.call('finish', '--run-dir', self.run)
        review = self.read(self.run / 'review.json')
        finding = review['findings'][0]
        finding['severity_assessment'].update(impact='core-blocked', context_id='merchant-confirmed-primary-flow-v2', basis='Fixture business profile establishes this handler as the sole primary operation.')
        finding['severity'] = 'High'
        finding['severity_change'] = dict(previous='Medium', type='context-change', reason='New business profile establishes sole primary-flow use.', evidence=['Fixture profile merchant-confirmed-primary-flow-v2 identifies the sole supported primary workflow.'])
        self.save(self.run / 'review.json', review)
        self.call('finish', '--run-dir', self.run)
        history = self.read(self.root / 'rscc/severity_registry.json')['history']
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['previous']['severity'], 'Medium')
        self.assertEqual(history[0]['replacement']['severity'], 'High')
        self.assertIn('Severity change:', (self.run / 'findings.md').read_text())

    def test_evidence_change_claim_without_changed_evidence_is_rejected(self):
        self.prepare_files()
        self.functional_finding()
        self.call('finish', '--run-dir', self.run)
        review = self.read(self.run / 'review.json')
        finding = review['findings'][0]
        finding['severity_assessment']['impact'] = 'core-blocked'
        finding['severity'] = 'High'
        finding['severity_change'] = dict(previous='Medium', type='evidence-change', reason='Claiming changed evidence without changed hashes.', evidence=['Fixture hash is unchanged.'])
        self.save(self.run / 'review.json', review)
        self.assertIn('Unchanged severity evidence', self.call('finish', '--run-dir', self.run, code=1).stderr)

    def test_severity_identity_matches_across_folder_and_file_modes(self):
        self.prepare()
        self.functional_finding(path='.hidden.php')
        self.call('finish', '--run-dir', self.run)
        first_key = self.read(self.run / 'review.json')['findings'][0]['stable_key']
        self.prepare_files([self.target / '.hidden.php'])
        self.functional_finding()
        self.call('finish', '--run-dir', self.run)
        second = self.read(self.run / 'review.json')['findings'][0]
        self.assertEqual(first_key, second['stable_key'])
        self.assertEqual(second['severity'], 'Medium')

    def test_drifting_run_does_not_establish_severity_baseline(self):
        self.prepare_files()
        self.functional_finding()
        (self.target / '.hidden.php').write_text('<?php changed_during_review();')
        self.call('finish', '--run-dir', self.run, code=2)
        self.assertFalse((self.root / 'rscc/severity_registry.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
