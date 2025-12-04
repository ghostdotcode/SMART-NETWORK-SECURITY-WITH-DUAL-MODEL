import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import os
import warnings

# Core Scikit-learn components
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, f1_score

# Models
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
import lightgbm as lgb

# --- MLflow for Experiment Tracking ---
# The industry standard for managing ML experiments. This is non-negotiable.
import mlflow
import mlflow.sklearn

warnings.filterwarnings('ignore')

# --- 1. SETUP: Configuration and Data Loading ---
print("Setting up the modeling pipeline...")

# Configuration
DATA_PATH = 'preprocessed_cybersecurity_data.csv'
TARGET_COLUMN = 'target_encoded'
TEST_SPLIT_SIZE = 0.2
RANDOM_STATE = 42
N_ITER_RANDOM_SEARCH = 25 # Number of parameter combinations to try. Higher is better but slower.

# Set up MLflow
# This will create a local 'mlruns' directory to store all your experiment data.
MLFLOW_EXPERIMENT_NAME = "Cybersecurity_Threat_Detection_v1"
mlflow.set_experiment(MLFLOW_EXPERIMENT_NAME)
print(f"MLflow experiment set to: '{MLFLOW_EXPERIMENT_NAME}'")

# Load data
try:
    df = pd.read_csv(DATA_PATH)
except FileNotFoundError:
    print(f"Error: Data file not found at '{DATA_PATH}'. Please ensure it's in the correct directory.")
    exit()

print(f"Dataset loaded successfully. Shape: {df.shape}")


# --- 2. FEATURE ENGINEERING & DATA PREPARATION ---
# Define features (X) and target (y)
print("Preparing features and target...")

# Drop columns that are irrelevant for modeling or are identifiers/leaky
# This is a more robust way to select features than listing them all out.
cols_to_drop = [
    'Added', 'Date', 'RayID', 'IP', 'Endpoint', 'User-Agent',
    'Country', 'Action taken', 'Added_datetime', 'Date_datetime',
    'time_window', 'browser_version', TARGET_COLUMN
]
# Ensure all columns in cols_to_drop actually exist in the DataFrame
valid_cols_to_drop = [col for col in cols_to_drop if col in df.columns]

X = df.drop(columns=valid_cols_to_drop)
y = df[TARGET_COLUMN]

# Get feature names for later use (e.g., feature importance)
feature_names = X.columns.tolist()

# Split data STRATIFIED to maintain target distribution in train/test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=TEST_SPLIT_SIZE, random_state=RANDOM_STATE, stratify=y
)
print(f"Data split into training ({X_train.shape}) and test ({X_test.shape}) sets.")


# --- 3. PIPELINE DEFINITION ---
# This is the core of a robust workflow. Pipelines chain preprocessing and modeling steps.
# This prevents data leakage and makes the code clean and reproducible.

# Preprocessing pipeline for numeric features:
# Step 1: Impute missing values with 0 (as before, but now explicit).
# Step 2: Scale features to have zero mean and unit variance.
numeric_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
    ('scaler', StandardScaler())
])

# Define models to be evaluated
# We use pipelines for each to bundle preprocessing and the estimator.
# Note: Even tree-based models can sometimes benefit from scaling, and it doesn't hurt.
# This approach simplifies the code by treating all models uniformly.
pipelines = {
    'RandomForest': Pipeline([
        ('preprocessor', numeric_transformer),
        ('classifier', RandomForestClassifier(random_state=RANDOM_STATE, class_weight='balanced', n_jobs=-1))
    ]),
    'XGBoost': Pipeline([
        ('preprocessor', numeric_transformer),
        ('classifier', xgb.XGBClassifier(random_state=RANDOM_STATE, eval_metric='mlogloss', use_label_encoder=False, n_jobs=-1))
    ]),
    'LightGBM': Pipeline([
        ('preprocessor', numeric_transformer),
        ('classifier', lgb.LGBMClassifier(random_state=RANDOM_STATE, class_weight='balanced', n_jobs=-1))
    ])
}

# --- 4. HYPERPARAMETER TUNING GRIDS (for RandomizedSearchCV) ---
# Using parameter distributions for efficient random search instead of exhaustive grid search.
param_distributions = {
    'RandomForest': {
        'classifier__n_estimators': [100, 200, 300, 400],
        'classifier__max_depth': [10, 20, 30, None],
        'classifier__min_samples_split': [2, 5, 10],
        'classifier__min_samples_leaf': [1, 2, 4],
        'classifier__max_features': ['sqrt', 'log2']
    },
    'XGBoost': {
        'classifier__n_estimators': [100, 200, 300, 400],
        'classifier__learning_rate': [0.01, 0.05, 0.1, 0.2],
        'classifier__max_depth': [3, 5, 7, 9],
        'classifier__subsample': [0.7, 0.8, 0.9, 1.0],
        'classifier__colsample_bytree': [0.7, 0.8, 0.9, 1.0],
        'classifier__gamma': [0, 0.1, 0.5, 1]
    },
    'LightGBM': {
        'classifier__n_estimators': [100, 200, 300, 400],
        'classifier__learning_rate': [0.01, 0.05, 0.1, 0.2],
        'classifier__max_depth': [3, 5, 7, -1],
        'classifier__num_leaves': [20, 31, 50, 70],
        'classifier__subsample': [0.7, 0.8, 0.9, 1.0],
        'classifier__colsample_bytree': [0.7, 0.8, 0.9, 1.0]
    }
}


# --- 5. MODEL TRAINING AND EVALUATION LOOP ---
print("\n" + "="*50)
print("Starting Model Training and Hyperparameter Tuning...")
print("="*50)

best_model_details = {
    'name': None,
    'f1_score': -1,
    'run_id': None
}

for name, pipeline in pipelines.items():
    print(f"\n--- Training {name} ---")

    # Start an MLflow run. Everything within this block will be logged together.
    with mlflow.start_run(run_name=f"Tune_{name}") as run:
        mlflow.log_param("model_name", name)

        # Randomized Search with Cross-Validation
        # SCORING METRIC IS CRITICAL: 'f1_weighted' is robust for imbalanced classes.
        random_search = RandomizedSearchCV(
            estimator=pipeline,
            param_distributions=param_distributions[name],
            n_iter=N_ITER_RANDOM_SEARCH,
            cv=3,
            scoring='f1_weighted',
            n_jobs=-1,
            random_state=RANDOM_STATE,
            verbose=0 # Set to 1 or 2 for more details
        )

        print("Fitting RandomizedSearchCV...")
        random_search.fit(X_train, y_train)

        # Get the best model found by the search
        best_estimator = random_search.best_estimator_

        # Evaluate on the test set
        print("Evaluating on test set...")
        y_pred = best_estimator.predict(X_test)
        report = classification_report(y_test, y_pred, output_dict=True)
        test_f1_weighted = report['weighted avg']['f1-score']

        # --- Logging to MLflow ---
        print("Logging results to MLflow...")
        mlflow.log_params(random_search.best_params_)
        mlflow.log_metric("cv_best_f1_weighted", random_search.best_score_)
        mlflow.log_metric("test_f1_weighted", test_f1_weighted)
        mlflow.log_metric("test_accuracy", report['accuracy'])
        mlflow.log_metric("test_precision_weighted", report['weighted avg']['precision'])
        mlflow.log_metric("test_recall_weighted", report['weighted avg']['recall'])

        # Log the trained model as an artifact
        mlflow.sklearn.log_model(best_estimator, f"{name}_model")

        print(f"✅ {name} - Test F1-Score: {test_f1_weighted:.4f} | CV Best F1-Score: {random_search.best_score_:.4f}")

        # Check if this is the best model so far
        if test_f1_weighted > best_model_details['f1_score']:
            best_model_details['name'] = name
            best_model_details['f1_score'] = test_f1_weighted
            best_model_details['run_id'] = run.info.run_id
            print(f"🏆 New best model found: {name}")


# --- 6. POST-TRAINING ANALYSIS & FINAL MODEL SELECTION ---
print("\n" + "="*50)
print("Model Training Complete. Analyzing Results...")
print("="*50)

print(f"\nBest performing model overall: {best_model_details['name']}")
print(f"Best F1-Score: {best_model_details['f1_score']:.4f}")
print(f"MLflow Run ID: {best_model_details['run_id']}")
print("\nTo view the detailed results, run 'mlflow ui' in your terminal.")

# Load the best model from MLflow
print("Loading the best model from MLflow artifacts...")
best_model_uri = f"runs:/{best_model_details['run_id']}/{best_model_details['name']}_model"
final_best_model = mlflow.sklearn.load_model(best_model_uri)

# Save the best model locally using pickle for easy access
with open('best_cybersecurity_model.pkl', 'wb') as f:
    pickle.dump(final_best_model, f)
print("Best model saved to 'best_cybersecurity_model.pkl'")

# --- 7. FEATURE IMPORTANCE ANALYSIS (for the best model only) ---
print("\nGenerating feature importance for the best model...")

# The actual classifier is the last step in our pipeline
classifier_step = final_best_model.steps[-1][1]

if hasattr(classifier_step, 'feature_importances_'):
    importances = classifier_step.feature_importances_
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    }).sort_values(by='importance', ascending=False)

    # Get top 20 features
    top_features = importance_df.head(20)

    # Visualization
    plt.style.use('dark_background')
    plt.figure(figsize=(12, 8))
    sns.barplot(x='importance', y='feature', data=top_features, palette='viridis')
    plt.title(f'Top 20 Feature Importances - {best_model_details["name"]}', fontsize=16, color='#00D4FF')
    plt.xlabel('Importance Score')
    plt.ylabel('Feature')
    plt.tight_layout()

    # Save the plot
    plt.savefig('best_model_feature_importance.png', dpi=300, bbox_inches='tight', facecolor='#2C3E50')
    print("Feature importance plot saved to 'best_model_feature_importance.png'")
    plt.close()
else:
    print(f"The best model ({best_model_details['name']}) does not support feature importances.")


print("\n✅ Pipeline execution finished successfully.")
