# https://github.com/Praneshss/PUF_Tutorial

import numpy as np

def get_parity_vectors(C):
    n = C.shape[1]
    m = C.shape[0]
    C[C == 0] = -1
    parityVec = np.zeros((m, n+1))
    parityVec[:, 0:1] = np.ones((m, 1))
    for i in range(2, n+2):
        parityVec[:, i -
                  1: i] = np.prod(C[:, 0: i-1], axis=1).reshape((m, 1))
    return parityVec
