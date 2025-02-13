from automata.fa.Moore import Moore
from automata.fa.Mealy import Mealy
import sys, os, string

from myerror import MyError

error_handler = MyError('LexerErrors')

global check_cm
global check_key
reservedWords = [
    'INT',
    'VOID',
    'FLOAT',
    'RETURN',
    'IF',
    'ELSE',
    'WHILE',
]

operators = {
    '+': 'PLUS',
    '-': 'MINUS',
    '*': 'TIMES',
    '/': 'DIVIDE',
    '<': 'LESS',
    '<=': 'LESS_EQUAL',
    '>': 'GREATER',
    '>=': 'GREATER_EQUAL',
    '==': 'EQUAL',
    '!=': 'DIFFERENT',
    '=': 'ATTRIBUTION',
}

digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# Não gera token necessariamente.
characters = list(string.ascii_lowercase) + list(string.ascii_uppercase)
specialCharacters = ['_', '$', '#', '@', '-']
breakCharacters = [' ', '\n']

separators = {
    '(': 'LPAREN',
    ')': 'RPAREN',
    '[': 'LBRACKETS',
    ']': 'RBRACKETS',
    '{': 'LBRACES',
    '}': 'RBRACES',
    ';': 'SEMICOLON',
    ',': 'COMMA',
}

transitions = {
    'q0': {
        'i': ('q1', ''),
        **{char: ('q5', '') for char in characters}
        # **{digit: 'q5' for digit in digits} Number
    },
    'q1': {
        'n': ('q2', ''),
        **{char: ('q5', '') for char in characters},
        **{digit: ('q5', '') for digit in digits}
    },
    'q2': {
        't': ('q3', ''),
        **{char: ('q5', '') for char in characters},
        **{digit: ('q5', '') for digit in digits}

    },
    'q3': {
        **{char: ('q4', 'INT') for char in breakCharacters},
        **{sepa: ('q4', 'INT') for sepa in separators}
    }
}

moore = Moore(['q0', 'q1', 'q2', 'q3', 'q4'],
              [operators.keys(), separators.keys(), digits,
               characters, specialCharacters, breakCharacters
               ],
              [reservedWords, operators.values(), separators.values(), 'NUM', 'ID'],
              {
                  'q0': {
                      'i': 'q1',
                  },
                  'q1': {
                      'n': 'q2',
                  },
                  'q2': {
                      't': 'q3',

                  },
                  'q3': {
                      '\n': 'q4',
                  }
              },

              'q0',
              {
                  'q0': '',
                  'q1': '',
                  'q2': '',
                  'q3': '',
                  'q4': 'INT'
              }
              )


mealy = Mealy(['q0', 'q1', 'q2', 'q3', 'q4'],
                [operators.keys(), separators.keys(), digits,
                 characters, specialCharacters, breakCharacters
                 ],
                [reservedWords, operators.values(), separators.values(), 'NUM', 'ID'],
                {
                    'q0': {
                        'i': 'q1',
                    },
                    'q1': {
                        'n': 'q2',

                    },
                    'q2': {
                        't': 'q3',

                    },
                    'q3': {
                        '\n': 'q4',
                    }
                },

                'q0',
                )


def main():
    check_cm = False
    check_key = False

    for idx, arg in enumerate(sys.argv):
        # print("Argument #{} is {}".format(idx, arg))
        aux = arg.split('.')
        if aux[-1] == 'cm':
            check_cm = True
            idx_cm = idx

        if (arg == "-k"):
            check_key = True

    # print ("No. of arguments passed is ", len(sys.argv))

    if (len(sys.argv) < 3):
        raise TypeError(error_handler.newError(check_key, 'ERR-LEX-USE'))

    if not check_cm:
        raise IOError(error_handler.newError(check_key, 'ERR-LEX-NOT-CM'))
    elif not os.path.exists(sys.argv[idx_cm]):
        raise IOError(error_handler.newError(check_key, 'ERR-LEX-FILE-NOT-EXISTS'))
    else:
        data = open(sys.argv[idx_cm])
        source_file = data.read()

        if not check_cm:
            print("Definição da Máquina")
            print(moore)
            print("Entrada:")
            print(source_file)
            print("Lista de Tokens:")

        # print(moore.get_output_from_string(source_file))


if __name__ == "__main__":

    try:
        main()
    except Exception as e:
        print(e)
    except (ValueError, TypeError) as e:
        print(e)