"""Inventory fixture only: never run this module."""

import pickle
import zipfile

import joblib
import torch
from safetensors.torch import load_file

pickle.load(open("clean.pkl", "rb"))
torch.load("weights.pt")
with zipfile.ZipFile("nested.zip") as bundle:
    pickle.loads(bundle.read("inner/model.pkl"))
joblib.load("compressed.joblib")


def dynamic(path):
    return pickle.load(open(path, "rb"))


load_file("weights.safetensors")
