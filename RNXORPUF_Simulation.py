import pypuf.simulation, pypuf.io, pypuf.attack, pypuf.metrics
import numpy
import numpy as np
from numpy.random import default_rng
from collections import Counter
from pypuf.simulation import ArbiterPUF
from pypuf.simulation import XORArbiterPUF
from pypuf.simulation import XORFeedForwardArbiterPUF
from pypuf.simulation import BistableRingPUF
from pypuf.simulation import XORBistableRingPUF
from pypuf.io import random_inputs
from pypuf.io import ChallengeResponseSet
from random import *


def RNXORPUF_sim(num_of_c):
    challenges = random_inputs(n=64, N=num_of_c, seed=123)

    print(f"C: {challenges}")
    print()

    NXOR_PUF_response = []
    NXOR_PUFMODE = []


    for i in range(0, len(challenges)):
        mode_select = 0
        unique, counts = numpy.unique(challenges[i], return_counts=True)
        count = dict(zip(unique, counts))
        print(count)
        ones = count[1]
        zeros= count[-1]
        print(f"Number of 1: {ones}")
        print(f"Number of 0: {zeros}")
        if(ones > zeros):
            print("ones > zeros: mode +1")
            mode_select += 1
        else:
            print("zeros > ones: mode +2")
            mode_select += 2

        print()
        even_pos = []
        for j in range(0, len(challenges[i]), 2):
            even_pos.append(challenges[i][j])

        evenpos_counter = Counter(even_pos)

        evenpos_ones = evenpos_counter[1]
        evenpos_zeros = evenpos_counter[-1]
        print(f"even position challenges count: {evenpos_counter}")
        print(f"Number of ones in even position: {evenpos_ones}")
        print(f"Number of zeros in even position: {evenpos_zeros}")

        if(evenpos_ones % 2 == 0):
            print("There are odd number of ones in even position: mode +1")
            mode_select += 1
        else:
            print("There are even number of ones in even position: mode +2")
            mode_select += 2

        print()
        odd_pos = []
        for j in range(1, len(challenges[i])+1, 2):
            odd_pos.append(challenges[i][j])

        odd_pos_counter = Counter(odd_pos)

        odd_pos_ones = odd_pos_counter[1]
        odd_pos_zeros = odd_pos_counter[-1]
        print(f"odd position challenges count: {odd_pos_counter}")
        print(f"Number of ones in even position: {odd_pos_ones}")
        print(f"Number of zeros in even position: {odd_pos_zeros}")

        if(odd_pos_ones % 2 == 0):
            print("There are odd number of ones in odd position: mode +1")
            mode_select += 1
        else:
            print("There are even number of ones in odd position: mode +2")
            mode_select += 2


        print(f"Mode: {mode_select}")
        print()


        challenge_reformat = np.array([challenges[i]])
        XOR_PUF = XORArbiterPUF(n=64, k=mode_select, seed=1)
        NXOR_response = XOR_PUF.eval(challenge_reformat)
        NXOR_PUF_response.append(NXOR_response[0])
        NXOR_PUFMODE.append(mode_select)


    print(f"NXOR responses: {NXOR_PUF_response}")
    print(f"PUF MODE: {NXOR_PUFMODE}")

    return challenges, NXOR_PUF_response

    
