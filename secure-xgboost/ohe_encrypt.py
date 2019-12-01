import os
import argparse
import csv
import pandas as pd
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder
from sklearn.compose import ColumnTransformer, make_column_transformer

TEMPFILE_NAME = 'tempohe1405.csv'


def ohe(input_path, column_names=None, column_indices=None):
    """always assumes that the input .csv has a header
    output, temp .csv never has a header"""
    df = pd.read_csv(input_path)
    if not column_names:
        mappings = dict(enumerate(df.columns))
        column_names = [mappings[i] for i in column_indices]
    preprocess = make_column_transformer(
            (FunctionTransformer(lambda x: x), list(set(df.columns) - set(column_names))),
            (OneHotEncoder(), column_names))
    ohe_arr = preprocess.fit_transform(df)
    with open(TEMPFILE_NAME, 'w') as f:
        writer = csv.writer(f)
        for i in range(len(ohe_arr)):
            row = ohe_arr[i].tolist()
            writer.writerow(row)


if __name__ == '__main__':

    os.system('make')

    parser = argparse.ArgumentParser()
    parser.add_argument('--input_path', help='path to the input .csv')
    parser.add_argument('--output_path', help='path to the folder the final encrypted file should be saved at')
    parser.add_argument('--column_names', nargs='*', help='column namesof categorical variables', required=False)
    parser.add_argument('--column_indices', nargs='*', help='column indices of categorical variables',  required=False)

    args = parser.parse_args()
    print(args.column_names)
    if args.column_names and args.column_indices:
        print('Warning: both categorical names and categorical indices are specified, defaulting to names')
    if args.column_names:
        ohe(args.input_path, column_names=args.column_names)
    elif args.column_indices:
        ohe(args.input_path, column_indices=args.column_indices)
    else:
        df = pd.read_csv(input_path)
        df.to_csv(TEMPFILE_NAME, header=False, index=False)

    os.system('./encrypt-file ' + TEMPFILE_NAME + ' ' + args.output_path)

    os.system('rm -f ' + TEMPFILE_NAME)

