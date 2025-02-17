from automata.fa.Mealy import Mealy
import sys, os, string, re

from myerror import MyError

error_handler = MyError('LexerErrors')

# Por algum motivo o teste não reconhecia se eu alterasse a função da classe Mealy, então eu forcei a substituição.
def my_get_output_from_string(self, string):
    current_state = self.initial_state
    tokens = []
    for char in string:
        # Se não houver transição para o caractere, ignore-o
        if char not in self.transitions[current_state]:
            continue
        next_state, token = self.transitions[current_state][char]
        current_state = next_state
        if token != "":
            tokens.append(token)
    return "\n".join(tokens)

Mealy.get_output_from_string = my_get_output_from_string


# Variáveis globais
DEBUG = False

# Tokens
reserved_words = [
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
    '==': 'EQUALS',
    '!': 'DIFFERENT',
    '=': 'ATTRIBUTION',
}

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


digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# Alfabeto de caracteres
characters = list(string.ascii_lowercase) + list(string.ascii_uppercase)
characters.append('_')
# Estados de inicias das palavras reservadas
reserved_initials = ['i', 'v', 'f', 'r', 'w', 'e']
# Caracteres de quebra
break_characters = [' ', '\n', '\t', '\r']
operator_states_transitions = {}
separators_states_transitions = {}


# Estados de comentarios
comment_states = ['q_comment*', 'q_comment/', 'q_comment*2']

# Estados de palavras reservadas
int_states = ['q_in', 'q_int']
void_states = ['q_vo', 'q_voi', 'q_void']
float_states = ['q_flo', 'q_floa', 'q_float']
return_states = ['q_re', 'q_ret', 'q_retu', 'q_retur', 'q_return']
else_states = ['q_els', 'q_else']
while_states = ['q_wh', 'q_whi', 'q_whil', 'q_while']


# Estados de operadores

for op in operators.keys():
    state_transitions = {
        **{rinit: ('q_reserved', operators[op]) for rinit in reserved_initials},
        **{ch: ('q0', operators[op]) for ch in break_characters},
        **{sep: (sep, operators[op]) for sep in separators.keys()},
        **{dig: ('q_digit', operators[op]) for dig in digits},
        **{char: ('q_id', operators[op]) for char in characters if char not in reserved_initials}
    }
    # Para os estados que precisam de tratamento especial:
    if op == '=':
        # Se estiver no estado '=' e ler outro '=', emite token "EQUAL"
        state_transitions['='] = ('q0', 'EQUALS')
        # Para outros operadores, exceto '='
        state_transitions.update({other: (other, operators[op]) for other in operators.keys() if other != '='})
    elif op == '<':
        state_transitions['='] = ('q0', 'LESS_EQUAL')
        state_transitions.update({other: (other, operators[op]) for other in operators.keys() if other != '='})
    elif op == '>':
        state_transitions['='] = ('q0', 'GREATER_EQUAL')
        state_transitions.update({other: (other, operators[op]) for other in operators.keys() if other != '='})
    elif op == '/':
        state_transitions['*'] = ('q_comment*', '')
        state_transitions['/'] = ('q_comment/', '')
        state_transitions.update({other: (other, operators[op]) for other in operators.keys() if other not in ['*', '/']})
    elif op == '!':
        state_transitions['='] = ('q0', 'DIFFERENT')
        state_transitions.update({other: (other, '') for other in operators.keys() if other != '='})
    else:
        state_transitions.update({other: (other, operators[op]) for other in operators.keys()})
    operator_states_transitions[op] = state_transitions


# Estados de separadores
for sep in separators.keys():
    state_transitions = {
        **{rinit: ('q_reserved', separators[sep]) for rinit in reserved_initials},
        **{ch: ('q0', separators[sep]) for ch in break_characters},
        **{op: (op, separators[sep]) for op in operators.keys()},
        **{dig: ('q_digit', separators[sep]) for dig in digits},
        **{char: ('q_id', separators[sep]) for char in characters if char not in reserved_initials},
        **{other: (other, separators[sep]) for other in separators.keys()}
    }
    separators_states_transitions[sep] = state_transitions

# Criando lista de estados da máquina
states_list = ['q0', 'q_reserved', 'q2', 'q3', 'q4', 'q_digit', 'q_id', 'q_if', 'q_xl']
states_list += list(operators.keys())
states_list += list(separators.keys())
states_list += int_states
states_list += comment_states
states_list += void_states
states_list += float_states
states_list += return_states
states_list += else_states
states_list += while_states



# Criando lista do alfabeto de entrada da máquina
input_alph = list(operators.keys())
input_alph += list(separators.keys())
input_alph += digits
input_alph += characters
input_alph += break_characters


# Criando lista do alfabeto de saída da máquina
output_alph = reserved_words
output_alph += list(operators.values())
output_alph += list(separators.values())
output_alph += ['NUMBER', 'ID']




mealy_transitions = {
    'q0': {
        **{rinit: ('q_reserved', '') for rinit in reserved_initials},
        '_': ('q_id', ''),
        **{char: ('q_id', '') for char in characters if char not in reserved_initials},
        **{bchar: ('q0', '') for bchar in break_characters},
        **{digit: ('q_digit', '') for digit in digits}, # Número
        **{oper: (oper, '') for oper in operators.keys()},
        **{sepa: (sepa, '') for sepa in separators.keys()},
    },
    'q_reserved': {
        'o': ('q_vo', ''),
        'l': ('q_xl', ''),
        'f': ('q_if',''),
        'n': ('q_in', ''),
        'e': ('q_re', ''),
        'h': ('q_wh', ''),
        **{char: ('q_id', '') for char in characters if char not  in ['f', 'n', 'o', 'l', 'e', 'h'] },
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_in': {
        't': ('q_int', ''),
        **{bchar: ('q0', 'D') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if not 't' in char},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},

    },
    'q_int': {
        **{bchar: ('q0', 'INT') for bchar in break_characters},
        **{sepa: (sepa, 'INT') for sepa in separators.keys()},
        **{oper: (oper, 'INT') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_id', '') for digit in digits}

    },
    'q_if': {
        **{bchar: ('q0', 'IF') for bchar in break_characters},
        **{sepa: (sepa, 'IF') for sepa in separators.keys()},
        **{oper: (oper, 'IF') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_id', '') for digit in digits}
    },
    **operator_states_transitions,
    **separators_states_transitions,
    'q_id': {
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_id', '') for digit in digits}
    },
    'q_digit': {
        **{bchar: ('q0', 'NUMBER') for bchar in break_characters},
        **{sepa: (sepa, 'NUMBER') for sepa in separators.keys()},
        **{oper: (oper, 'NUMBER') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_digit', '') for digit in digits}
    },
    'q_xl': {
        's': ('q_els', ''),
        'o': ('q_flo', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char not in ['s', 'o']},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_els': {
        'e': ('q_else', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'e'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_else': {
        **{bchar: ('q0', 'ELSE') for bchar in break_characters},
        **{sepa: (sepa, 'ELSE') for sepa in separators.keys()},
        **{oper: (oper, 'ELSE') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_id', '') for digit in digits}
    },
    'q_flo': {
        'a': ('q_floa', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'a'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_floa': {
        't': ('q_float', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 't'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_float': {
        **{bchar: ('q0', 'FLOAT') for bchar in break_characters},
        **{sepa: (sepa, 'FLOAT') for sepa in separators.keys()},
        **{oper: (oper, 'FLOAT') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_id', '') for digit in digits}
    },
    'q_re': {
        't': ('q_ret', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 't'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_ret': {
        'u': ('q_retu', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'u'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_retu': {
        'r': ('q_retur', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'r'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_retur': {
        'n': ('q_return', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'n'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_return': {
        **{bchar: ('q0', 'RETURN') for bchar in break_characters},
        **{sepa: (sepa, 'RETURN') for sepa in separators.keys()},
        **{oper: (oper, 'RETURN') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_id', '') for digit in digits}
    },
    'q_wh': {
        'i': ('q_whi', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'i'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_whi': {
        'l': ('q_whil', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'l'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_whil': {
        'e': ('q_while', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'e'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_while': {
        **{bchar: ('q0', 'WHILE') for bchar in break_characters},
        **{sepa: (sepa, 'WHILE') for sepa in separators.keys()},
        **{oper: (oper, 'WHILE') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_id', '') for digit in digits}
    },
    'q_vo': {
        'i': ('q_voi', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'i'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_voi': {
        'd': ('q_void', ''),
        **{bchar: ('q0', 'ID') for bchar in break_characters},
        **{char: ('q_id', '') for char in characters if char != 'd'},
        **{digit: ('q_id', '') for digit in digits},
        **{oper: (oper, 'ID') for oper in operators.keys()},
        **{sepa: (sepa, 'ID') for sepa in separators.keys()},
    },
    'q_void': {
        **{bchar: ('q0', 'VOID') for bchar in break_characters},
        **{sepa: (sepa, 'VOID') for sepa in separators.keys()},
        **{oper: (oper, 'VOID') for oper in operators.keys()},
        **{char: ('q_id', '') for char in characters},
        **{digit: ('q_id', '') for digit in digits}
    },
    'q_comment*': {
        '*': ('q_comment*2', ''),
        **{bchar: ('q_comment*', '') for bchar in break_characters},
        **{sepa: ('q_comment*', '') for sepa in separators.keys()},
        **{oper: ('q_comment*', '') for oper in operators.keys() if oper != '*'},
        **{char: ('q_comment*', '') for char in characters},
        **{digit: ('q_comment*', '') for digit in digits}

    },
    'q_comment*2': {
        '/': ('q0', ''),
        '*': ('q_comment*2', ''),
        **{bchar: ('q_comment*', '') for bchar in break_characters},
        **{sepa: ('q_comment*', '') for sepa in separators.keys()},
        **{oper: ('q_comment*', '') for oper in operators.keys() if oper not in ['/', '*']},
        **{char: ('q_comment*', '') for char in characters},
        **{digit: ('q_comment*', '') for digit in digits}
    },
    'q_comment/': {
        '\n': ('q0', ''),
        **{bchar: ('q_comment/', '') for bchar in break_characters},
        **{sepa: ('q_comment/', '') for sepa in separators.keys()},
        **{oper: ('q_comment/', '') for oper in operators.keys() if oper != '/'},
        **{char: ('q_comment/', '') for char in characters},
        **{digit: ('q_comment/', '') for digit in digits}
    },

}


mealy = Mealy(states_list,
                input_alph,
                output_alph,
                mealy_transitions,
                'q0'
)

check_file = False
def main():
    global check_cm
    global check_key
    global check_file

    check_cm = False
    check_key = False
    check_file = False

    idx_cm = 0

    match_cm = r"[\w\W]*.cm$"  # arquivo com fim cm
    match_not_cm = r"[\w\W]*\.[\w]+$"  # arquivo not cm != arquivo com fim not cm

    for idx, arg in enumerate(sys.argv[1:]):

        if re.match(match_not_cm, arg):
            check_file = True
            idx_cm = idx + 1

            if re.match(match_cm, arg):
                check_cm = True

        if arg == "-k":
            check_key = True

    if not check_file:
        raise TypeError(error_handler.newError(check_key, 'ERR-LEX-USE'))
    if not check_cm:
        raise IOError(error_handler.newError(check_key, 'ERR-LEX-NOT-CM'))
    elif not os.path.exists(sys.argv[idx_cm]):
        raise IOError(error_handler.newError(check_key, 'ERR-LEX-FILE-NOT-EXISTS'))
    else:
        data = open(sys.argv[idx_cm])

        source_file = data.read()

        # Verifica se há caracteres inválidos no arquivo
        for char in source_file:
            if char not in input_alph:
                raise ValueError(error_handler.newError(check_key, 'ERR-LEX-INV-CHAR'))


        if not check_key:
            print("Definição da Máquina")
            print(mealy)
            print("Entrada:")
            print(source_file)
            print("Entrada:")

        print(mealy.get_output_from_string(source_file))


        if DEBUG:
            print("Estados definidos:", states_list)
            print("Alfabeto de entrada:", input_alph)
            print("Alfabeto de saída:", output_alph)



if __name__ == "__main__":

    try:
        main()
    except Exception as e:
        print(e)
    except (ValueError, TypeError) as e:
        print(e)
