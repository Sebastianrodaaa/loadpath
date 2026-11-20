import textwrap

import pytest

from loadpath.inventory import scan


def inventory(tmp_path, source):
    path = tmp_path / "app.py"
    path.write_text(textwrap.dedent(source))
    findings, errors = scan(path)
    assert not errors
    return findings


@pytest.mark.parametrize(
    "source,loader,rule",
    [
        ("import pickle as p; p.load('x')", "pickle.load", "LP001"),
        ("from pickle import loads as pl; pl(data)", "pickle.loads", "LP001"),
        ("from pickle import Unpickler as U; U('x')", "pickle.Unpickler", "LP001"),
        ("import cPickle; cPickle.load('x')", "cPickle.load", "LP001"),
        ("import _pickle; _pickle.loads(data)", "_pickle.loads", "LP001"),
        ("import dill; dill.load('x')", "dill.load", "LP002"),
        ("import cloudpickle; cloudpickle.loads(data)", "cloudpickle.loads", "LP002"),
        ("from joblib import load as jl; jl('x')", "joblib.load", "LP003"),
        ("import torch as t; t.load('x')", "torch.load", "LP004"),
        ("import torch.jit as tj; tj.load('x')", "torch.jit.load", "LP005"),
        ("import numpy as np; np.load('x', allow_pickle=True)", "numpy.load", "LP006"),
        ("import pandas as pd; pd.read_pickle('x')", "pandas.read_pickle", "LP007"),
        ("from keras.models import load_model; load_model('x.h5')", "keras.models.load_model", "LP008"),
        ("import tensorflow as tf; tf.keras.models.load_model('x')", "tensorflow.keras.models.load_model", "LP008"),
        ("import tensorflow as tf; tf.saved_model.load('x')", "tensorflow.saved_model.load", "LP009"),
        ("from transformers import AutoModel as AM; AM.from_pretrained('repo', trust_remote_code=True)", "transformers.AutoModel.from_pretrained", "LP010"),
        ("from huggingface_hub import snapshot_download; snapshot_download('repo')", "huggingface_hub.snapshot_download", "LP011"),
        ("import skops.io as sio; sio.load('x', trusted=['custom.Type'])", "skops.io.load", "LP012"),
        ("from safetensors.torch import load_file as lf; lf('x')", "safetensors.torch.load_file", "LP013"),
        ("from safetensors import safe_open; safe_open('x')", "safetensors.safe_open", "LP013"),
    ],
)
def test_rules_and_aliases(tmp_path, source, loader, rule):
    found = inventory(tmp_path, source)
    assert len(found) == 1
    assert (found[0].loader, found[0].rule) == (loader, rule)
    assert found[0].line == 1 and found[0].col > 1


@pytest.mark.parametrize(
    "loader,flags,severity",
    [
        ("torch.load", "", "high"),
        ("torch.load", ", weights_only=False", "high"),
        ("torch.load", ", weights_only=True", "low"),
        ("torch.load", ", weights_only=flag", "high"),
        ("torch.load", ", weights_only=True, pickle_module=custom", "high"),
        ("torch.load", ", weights_only=True, **options", "high"),
        ("numpy.load", ", allow_pickle=True", "high"),
        ("numpy.load", ", allow_pickle=False", "low"),
        ("numpy.load", ", allow_pickle=flag", "medium"),
        ("keras.models.load_model", ", safe_mode=False", "high"),
        ("keras.models.load_model", ", safe_mode=True", "medium"),
        ("transformers.AutoModel.from_pretrained", ", trust_remote_code=True", "high"),
        ("transformers.AutoModel.from_pretrained", ", trust_remote_code=False", "low"),
    ],
)
def test_risk_args(tmp_path, loader, flags, severity):
    found = inventory(tmp_path, f"import {loader.split('.')[0]}\n{loader}('x'{flags})")
    assert found[0].severity == severity


def test_paths_and_scope(tmp_path):
    found = inventory(
        tmp_path,
        """
        import pickle
        import os as operating
        from pathlib import Path as P
        ROOT = 'models'
        A = operating.path.join(ROOT, 'a.pkl')
        pickle.load(open(A, 'rb'))
        def local():
            A = P('local') / 'b.pkl'
            with A.open('rb') as stream:
                pickle.load(stream)
        pickle.load(open(A, 'rb'))
        pickle.load(open(f'{ROOT}/a.pkl', 'rb'))
    """,
    )
    assert [f.resolved_artifact for f in found] == ["models/a.pkl", "local/b.pkl", "models/a.pkl", None]
    assert found[0].expression == "open(A, 'rb')"


def test_shadowing_and_parameter(tmp_path):
    found = inventory(
        tmp_path,
        """
        import torch as t
        import pickle
        X = 'module.pkl'
        def f(X):
            pickle.load(X)
        def g():
            pickle.load(X)
            X = 'later.pkl'
        t = object()
        t.load('not-torch')
    """,
    )
    assert len(found) == 2 and all(f.resolved_artifact is None for f in found)


def test_branch_merges(tmp_path):
    found = inventory(
        tmp_path,
        """
        import pickle
        if flag:
            P = 'a'
        else:
            P = 'b'
        pickle.load(P)
        if flag:
            P = 'same'
        else:
            P = 'same'
        pickle.load(P)
        for x in paths:
            P = x
        pickle.load(P)
    """,
    )
    assert [f.resolved_artifact for f in found] == [None, "same", None]


def test_positional_and_keywords(tmp_path):
    found = inventory(
        tmp_path,
        """
        import numpy
        import keras
        import torch
        numpy.load('x', None, True)
        keras.models.load_model('x', None, True, False)
        torch.load(f='weights.pt', weights_only=False)
    """,
    )
    assert all(f.severity == "high" for f in found)
    assert found[-1].resolved_artifact == "weights.pt"


def test_download_context(tmp_path):
    found = inventory(
        tmp_path,
        """
        import torch
        from huggingface_hub import hf_hub_download as fetch
        path = fetch(repo_id='owner/repo', filename='weights.pt')
        torch.load(path)
    """,
    )
    assert [f.rule for f in found] == ["LP011", "LP004"]
    assert all(f.resolved_artifact is None for f in found)
    assert found[-1].context[0].startswith("download:")


def test_archive_context(tmp_path):
    found = inventory(
        tmp_path,
        """
        import pickle
        from zipfile import ZipFile
        with ZipFile('bundle.zip') as z:
            pickle.loads(z.read('model.pkl'))
    """,
    )
    assert found[0].resolved_artifact == "bundle.zip"
    assert found[0].context == ["archive: bundle.zip", "member: model.pkl"]


def test_dynamic_archive_stays_unresolved(tmp_path):
    found = inventory(
        tmp_path,
        """
        import pickle
        from zipfile import ZipFile
        with ZipFile(dynamic) as z:
            pickle.loads(z.read('model.pkl'))
            pickle.load(z.open('model.pkl'))
    """,
    )
    assert len(found) == 2 and all(f.resolved_artifact is None for f in found)


def test_legacy_keras(tmp_path):
    f = inventory(tmp_path, "import keras; keras.models.load_model('x.h5', safe_mode=True)")[0]
    assert f.severity == "high" and "Lambda" in f.message


def test_empty_error_and_no_execution(tmp_path):
    assert inventory(tmp_path, "") == []
    assert inventory(tmp_path, "raise RuntimeError('must not execute')") == []
    (tmp_path / "bad.py").write_text("def broken(")
    assert scan(tmp_path)[1]
    with pytest.raises(ValueError, match="does not exist"):
        scan(tmp_path / "absent")


@pytest.mark.parametrize("expression", [
    "[pickle.load(P) for P in paths]",
    "{pickle.load(P) for P in paths}",
    "{P: pickle.load(P) for P in paths}",
    "(pickle.load(P) for P in paths)",
])
def test_comprehension_targets_are_local(tmp_path, expression):
    found = inventory(tmp_path, "import pickle\nP = 'outer.pkl'\n" + expression + "\npickle.load(P)")
    assert [f.resolved_artifact for f in found] == [None, "outer.pkl"]


def test_comprehension_does_not_hide_function_binding(tmp_path):
    found = inventory(tmp_path, """
        import pickle
        P = 'outer.pkl'
        def f():
            pickle.load(P)
            return [P for P in paths]
    """)
    assert [f.resolved_artifact for f in found] == ["outer.pkl"]


def test_class_attributes_are_not_method_bindings(tmp_path):
    found = inventory(tmp_path, """
        import pickle
        P = 'outer.pkl'
        class Model:
            P = 'class.pkl'
            pickle.load(P)
            def load(self):
                pickle.load(P)
            outputs = [pickle.load(P) for item in items]
        pickle.load(P)
    """)
    assert [f.resolved_artifact for f in found] == ["class.pkl", "outer.pkl", "outer.pkl", "outer.pkl"]


def test_class_in_function_keeps_lexical_binding(tmp_path):
    found = inventory(tmp_path, """
        import pickle
        def outer():
            P = 'closure.pkl'
            class Model:
                P = 'class.pkl'
                def load(self):
                    pickle.load(P)
    """)
    assert [f.resolved_artifact for f in found] == ["closure.pkl"]


def test_comprehension_iterators_filters_and_walrus(tmp_path):
    found = inventory(tmp_path, """
        import pickle
        P = 'outer.pkl'
        values = [pickle.load(P) for item in pickle.load(P) for P in paths if pickle.load(P)]
        [(P := dynamic) for item in items]
        pickle.load(P)
    """)
    assert [f.resolved_artifact for f in found] == [None, "outer.pkl", None, None]


def test_lambda_and_nested_class_scopes(tmp_path):
    found = inventory(tmp_path, """
        import pickle
        P = 'outer.pkl'
        f = lambda P: pickle.load(P)
        class Outer:
            P = 'class.pkl'
            class Inner:
                pickle.load(P)
            outputs = [pickle.load(item) for item in pickle.load(P)]
        class NoOuterBinding:
            Q = 'class.pkl'
            def load(self):
                pickle.load(Q)
        pickle.load(P)
    """)
    assert [f.resolved_artifact for f in found] == [None, "outer.pkl", None, "class.pkl", None, "outer.pkl"]


@pytest.mark.parametrize("statement", [
    "del cache[pickle.load(P)]",
    "cache[pickle.load(P)] = 1",
    "pickle.load(P).attribute = 1",
    "del pickle.load(P).attribute",
    "cache[pickle.load(P)]: object = 1",
    "cache[pickle.load(P)]: object",
    "[item for cache[pickle.load(P)] in items]",
    "[item for pickle.load(P).attribute in items]",
    "[item for (name, cache[pickle.load(P)]) in items]",
    "with manager() as cache[pickle.load(P)]:\n    pass",
    "cache[pickle.load(P)] += 1",
    "for cache[pickle.load(P)] in items:\n    pass",
])
def test_loader_calls_in_targets(tmp_path, statement):
    found = inventory(tmp_path, "import pickle\nP = 'outer.pkl'\n" + statement + "\npickle.load(P)")
    assert [f.resolved_artifact for f in found] == ["outer.pkl", "outer.pkl"]


def test_assignment_target_runs_after_rhs(tmp_path):
    found = inventory(tmp_path, "import pickle\nP = 'outer.pkl'\ncache[pickle.load(P)] = (P := dynamic)")
    assert len(found) == 1 and found[0].resolved_artifact is None
