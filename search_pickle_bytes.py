p='best_cybersecurity_model.pkl'
with open(p,'rb') as f:
    b=f.read()
patterns=[b'RandomForest', b'RandomForestClassifier', b'XGB', b'XGBClassifier', b'gbtree', b'lightgbm', b'LGBM', b'LGBMClassifier', b'sklearn', b'Pipeline']
for s in patterns:
    print(s.decode('latin1'), (s in b))
# print a few surrounding bytes for matches
for s in patterns:
    idx=b.find(s)
    if idx!=-1:
        start=max(0,idx-40)
        end=min(len(b), idx+len(s)+40)
        print('\nMATCH:', s.decode('latin1'))
        print(b[start:end])
