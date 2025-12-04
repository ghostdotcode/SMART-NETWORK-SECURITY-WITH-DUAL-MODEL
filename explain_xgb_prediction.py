import pickle
import pandas as pd
import numpy as np
import xgboost as xgb
import json

MODEL_PKL = 'best_cybersecurity_model.pkl'
DATA_CSV = 'preprocessed_cybersecurity_data.csv'

print('Loading model...')
with open(MODEL_PKL, 'rb') as f:
    model = pickle.load(f)
print('Loaded model type:', type(model))

# If model is an sklearn Pipeline, find the classifier (XGBClassifier) and preprocessor
clf = None
preprocessor = None
feature_names = None

try:
    # If Pipeline-like
    from sklearn.pipeline import Pipeline
    if isinstance(model, Pipeline):
        steps = dict(model.named_steps)
        print('Pipeline steps:', list(steps.keys()))
        # assume classifier is last step
        clf = list(steps.values())[-1]
        preprocessor = list(steps.values())[0]
        # try to get feature names from preprocessor
        try:
            feature_names = preprocessor.get_feature_names_out()
        except Exception:
            feature_names = None
    else:
        clf = model
except Exception:
    clf = model

print('Classifier type:', type(clf))

# Load data
print('Loading preprocessed data...')
df = pd.read_csv(DATA_CSV)
print('Data shape:', df.shape)

# Choose a row to explain
row_idx = 0
row = df.iloc[[row_idx]]
print('\nUsing row index', row_idx)
print(row.head(1).T)

# Determine features to pass
X = row

# If preprocessor exists and gives feature names, ensure we pass appropriate columns
if feature_names is not None:
    print('Preprocessor feature names count:', len(feature_names))
    # If feature_names are like 'x0', assume preprocessor expects numeric array; pass full df

# Transform using pipeline if available
if hasattr(model, 'predict_proba') and not hasattr(model, 'named_steps'):
    # model is classifier directly
    print('Model supports predict_proba directly')

# Use pipeline to get transformed matrix for classifier if pipeline exists
X_for_clf = None
if hasattr(model, 'named_steps'):
    # pipeline: use all steps except the final classifier to produce transformed features
    steps = list(model.named_steps.items())
    if len(steps) >= 2:
        # apply all but last
        from sklearn.pipeline import Pipeline
        preproc_pipe = Pipeline(steps[:-1])
        X_trans = preproc_pipe.transform(X)
        try:
            # attempt to get transformed feature names
            trans_feature_names = preproc_pipe.get_feature_names_out(X.columns)
        except Exception:
            trans_feature_names = None
        print('Transformed shape:', X_trans.shape)
        X_for_clf = X_trans
    else:
        # no preprocessor
        X_for_clf = X.values
else:
    # model not pipeline
    X_for_clf = X.values

# If classifier is XGBClassifier inside pipeline, extract booster
xgb_clf = None
try:
    # common attribute name
    if hasattr(clf, 'get_booster'):
        xgb_clf = clf
    else:
        # sometimes pipeline final step is object with 'booster_' or 'get_booster'
        if hasattr(model, 'named_steps'):
            last = list(model.named_steps.values())[-1]
            if hasattr(last, 'get_booster'):
                xgb_clf = last

    print('XGBoost classifier found:', xgb_clf is not None)
except Exception as e:
    print('Error checking XGB classifier:', e)

if xgb_clf is None:
    print('No XGBoost classifier found, exiting')
    raise SystemExit

# Create DMatrix from transformed features
if X_for_clf is None:
    X_for_clf = X.values

# If classifier is sklearn wrapper, it may expect original columns and perform preprocessing internally
# but booster expects raw feature array; get the booster and feature names from it
booster = xgb_clf.get_booster()
print('Booster type:', type(booster))

# If we have transformed feature array, pass that; else pass original
# Convert to DMatrix
# Note: if the pipeline included scaling, X_for_clf is numeric array ready for booster
if isinstance(X_for_clf, pd.DataFrame):
    data_for_dmatrix = X_for_clf.values
else:
    data_for_dmatrix = X_for_clf

dmat = xgb.DMatrix(data_for_dmatrix)

# Get raw scores (margin) per class
raw_margin = booster.predict(dmat, output_margin=True)
print('\nRaw margin output (per class logits)')
print(raw_margin)

# If multiclass, shape is (n_rows, n_classes)
if raw_margin.ndim == 1:
    # binary or single value
    logits = raw_margin
else:
    logits = raw_margin[0]

# Compute softmax to get probabilities
def softmax(z):
    e = np.exp(z - np.max(z))
    return e / e.sum()

probs = softmax(logits)
print('\nSoftmax probabilities')
print(probs)

# Get tree dump for first few trees
print('\nDumping first 3 trees (text)')
dump = booster.get_dump(dump_format='text')
for i, tree in enumerate(dump[:3]):
    print('\n--- Tree', i, '---')
    print(tree)

# Also show per-tree contributions by predicting with output_margin=False per tree is not straightforward,
# but we can compute predicted margin and show that margin = sum leaf outputs across trees.

# Print brief explanation file
explanation = {
    'row_index': row_idx,
    'raw_margin': raw_margin.tolist() if hasattr(raw_margin, 'tolist') else [float(raw_margin)],
    'probabilities': probs.tolist()
}
print('\nExplanation summary (JSON):')
print(json.dumps(explanation, indent=2))

