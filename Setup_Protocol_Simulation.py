import pypuf.simulation, pypuf.io, pypuf.attack, pypuf.metrics
import string
import numpy as np
import pandas as pd
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
import random
import csv
import hashlib
import hmac
from cryptography.fernet import Fernet

def setup():

    PUF_seed = random.randint(0, 999)

    print("==============================")
    print("Setup Phrase Started")
    #generates a DID, length of 8
    print("Device generating DID")
    DID = "Device_"+"".join(np.random.choice(list(string.ascii_uppercase + string.digits))for i in range(8))
    SID = "Demo_Server"
    print("Server Predefined as " + SID)
    print("==============================")
    print("DID: " + DID)
    print("SID: " + SID)
    print("==============Device================")
    print("Device get current DID")
    print("Device sending Reg1: {DID} to Server")
    print()
    print("==============Server================")
    print("Server received Reg1")
    print("Server generating eK, hK, C")
    print()
    eK = Fernet.generate_key()
    hK = "".join(np.random.choice(list(string.digits))for i in range(8))
    # generates a challenge of 64 bit in length of 8 using seed 123
    challenges = random_inputs(n=64, N=8, seed=PUF_seed)
    print(f"Encryption Key eK: {eK}")
    print(f"Hash Salt Key hK: {hK}")
    print(f"Challenge C: {challenges[0]}...")
    print()
    print("Storing Reg1: {DID, eK, hK} to Server_Storage")
    print()
    print("==============Server_Storage================")
    Server_Storage = {'DID': [DID], 'eK': [eK], 'hK': [hK]}
    Server_Storage_df = pd.DataFrame(data=Server_Storage)
    print(Server_Storage_df.to_string(index=False))
    print("============================================")
    print()
    print("Server sending Reg2: {SID, eK, hK, C} to Device")
    print()

    print("==============Device================")
    print("Device received Reg2")
    print("Storing Reg2: {SID, eK, hK, C} to Secure-NVM")
    print()
    print("==============Device_Storage================")
    Device_Storage = {'SID':[SID], 'eK':[eK], 'hK':[hK]}
    Device_Storage_df = pd.DataFrame(data=Device_Storage)
    print(Device_Storage_df.to_string(index=False))
    print("============================================")
    print("Generating response using PUF")
    Arbiter = ArbiterPUF(n=64, seed=1)
    response = Arbiter.eval(challenges)
    print(f"Response R: {response}")
    print("Device sending Reg3: {R} to Server")
    print()
    print("==============Server================")
    print("Server received Reg3 to Server_Storage")
    print("Storing Reg3: {R}")
    print("==============Server_Storage================")
    Server_Storage = {'DID': [DID], 'C': [str(challenges).replace("-1", "0").replace(" ","").replace("[","").replace("]",",").replace(" ","")], 'R': [str(response).replace("-1", "0").replace(" ","").replace("[","").replace("]","")], 'eK': [eK], 'hK': [hK]}
    Server_Storage_df = pd.DataFrame(data=Server_Storage)
    print(Server_Storage_df)
    print("============================================")
    print()
    print("Setup Phrase Ended")
    print()
    print("================Current_Server_Database================")
    read_server_csv = pd.read_csv("setup_server.csv", sep=',', encoding="utf-8")
    new_csv = pd.concat([read_server_csv,Server_Storage_df])
    print(new_csv)
    new_csv.to_csv('setup_server.csv',encoding='utf-8', index=False)
    print()


    print("================Current_Device_Details================")
    print("DID: " + DID)
    print("SID: " + SID)
    print("PUF seed: " + str(PUF_seed))
    print("eK: " + str(eK))
    print("hK: " + hK)
    print()












