# tokens.py
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