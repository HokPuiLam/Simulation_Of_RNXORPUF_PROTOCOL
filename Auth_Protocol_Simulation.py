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
import csv
import hashlib
import hmac
from cryptography.fernet import Fernet
import random



# DID = "Device_5UOWTPTQ"
# SID = "Demo_Server"
# PUF_seed = 683
# eK = b'eBlZLcfNDsnzpfyN5zP7Y37QoL9ZBfUUSVp9QDGEXmA='
# hK = 73149145
# print(eK)
# print(type(eK))



def auth(DID, SID,PUF_seed, eK, hK):




    read_server_csv = pd.read_csv("setup_server.csv", sep=',', encoding="utf-8")

    print("============Auth Phrase Started================")
    print()
    print("==============Device_Properties================")
    print("DID: " + DID)
    print("SID: " + SID)
    print("PUF seed: " + str(PUF_seed))
    print("eK: " + str(eK))
    print("hK: " + str(hK))
    print("===============================================")
    print()
    print("===================Device======================")
    print("Generating Session Key sK")
    sK = "".join(np.random.choice(list(string.digits))for i in range(8))
    print("sK: " + sK)
    print()
    print("Computing Verify Key-Hash V0 (SHA-1)")
    DIDsK_concat = DID + sK
    DIDsK_concat_bytes = bytes(DIDsK_concat, 'UTF-8')
    hK_bytes = bytes(str(hK), 'UTF-8')
    V0 = hmac.new(DIDsK_concat_bytes, hK_bytes, hashlib.sha1)
    print("V0: " + str(V0.digest()))
    print()
    print("Computing Encrypted Verify Key-Hash EV0")
    f = Fernet(eK)
    sKV0_concat_bytes = V0.digest() + bytes("  ", 'UTF-8') + bytes(sK, 'UTF-8')
    EV0 = f.encrypt(sKV0_concat_bytes)
    print("EV0: " + str(EV0))
    print()
    print("Device sending M1: {DID, EV0} to Server")
    print("===============================================")
    print()
    print("===================Server======================")
    print("Load SID")
    print("SID: " + SID)
    print()
    print(f"Finding DID: {DID} in database")

    read_server_csv = pd.read_csv("setup_server.csv", sep=',', encoding="utf-8")


    try:

        server_DID = read_server_csv.loc[read_server_csv['DID'] == DID]['DID'].iloc[0]
        print(f"DID: {DID} found in database. Now Reading C, R, eK, hK.")
        server_C = read_server_csv.loc[read_server_csv['DID'] == DID]['C'].iloc[0]
        server_R = read_server_csv.loc[read_server_csv['DID'] == DID]['R'].iloc[0]
        server_eK = read_server_csv.loc[read_server_csv['DID'] == DID]['eK'].iloc[0]
        server_hK = read_server_csv.loc[read_server_csv['DID'] == DID]['hK'].iloc[0]
        print(f"C: {server_C[:20]}...")
        print(f"R: {server_R}")
        print(f"eK: {server_eK}")
        print(f"hK: {server_hK}")
        server_sK_v0 = f.decrypt(EV0)

        server_sK_v0 = str(server_sK_v0).split("  ")



        print(f"Server Decrypting EV0")
        M1_V0 = str(server_sK_v0[0])+(server_sK_v0[0][1])
        M1_sK = str(server_sK_v0[1][:-1])
        print(f"M1 sK: {M1_sK}")
        print(f"M1 V0: {M1_V0}")
        M1_DID_concat_sK = DID + M1_sK
        M1_DID_concat_sK_bytes = bytes(str(M1_DID_concat_sK), 'UTF-8')
        server_compute_V0 = hmac.new(M1_DID_concat_sK_bytes, bytes(str(server_hK), 'UTF-8'), hashlib.sha1)
        print()
        print(f"Verifying V0")
        if(M1_V0 == str(server_compute_V0.digest())):
            print("V0 successfully verified")
            print(f"M1_V0: {M1_V0}")
            print(f"computed_V0: {str(server_compute_V0.digest())}")
            print()
            print("Computing Verify Key-Hash V1 (SHA-1)")
            SIDsK_concat = SID + sK
            SIDsK_concat_bytes = bytes(SIDsK_concat, 'UTF-8')
            hK_bytes = bytes(str(hK), 'UTF-8')
            V1 = hmac.new(SIDsK_concat_bytes, hK_bytes, hashlib.sha1)
            print("V1: " + str(V1.digest()))
            print()
            print("Computing Encrypted Verify Key-Hash EV1")
            server_c_arr = server_C.split(",")
            temp = []
            for row in server_c_arr:
                temp.append(row)
            C1 = list(filter(None, temp))
            C1_str = str(C1)

            f = Fernet(eK)
            sKCV1_concat_bytes = V1.digest() + bytes("  ", 'UTF-8') + bytes(sK, 'UTF-8') + bytes("  ", 'UTF-8') + bytes(C1_str, 'UTF-8')
            EV1 = f.encrypt(sKCV1_concat_bytes)
            print(f"EV1: {EV1[:50]}...")
            print()
            print("Server sending M2: {SID, EV1} to Device")
            print()
            print("===================Device======================")
            print(f"Finding SID: {SID} in Secure-NVM")
            if(SID == "Demo_Server"):
                print("SID verified")
                print("Reading eK, hK from secure-NVM")
                print(f"eK: {eK}")
                print(f"hK: {hK}")
                print()
                print(f"Device Decrypting EV1")
                device_sKCV1 = f.decrypt(EV1)
                device_sKCV1 = str(device_sKCV1).split("  ")
                M2_V1 = str(device_sKCV1[0])+(device_sKCV1[0][1])
                M2_sK = str(device_sKCV1[1])
                M2_C = str(device_sKCV1[2][:-1])
                print(f"M2 sK: {M2_sK}")
                print(f"M2 V1: {M2_V1}")
                M2_C_arr = M2_C.replace("\n","").replace("\\n","").replace("\\","").replace("'","").replace("[","").replace("]","").split(",")
                print(f"M2 C: {M2_C_arr[0]}...")
                print()
                print(f"Verifying V1")
                M2_SID_sK_concat = SID + M2_sK
                M2_SID_sK_concat_bytes = bytes(str(M2_SID_sK_concat), 'UTF-8')
                server_compute_V1 = hmac.new(M2_SID_sK_concat_bytes, bytes(str(server_hK), 'UTF-8'), hashlib.sha1)
                standardized_M2_V1 = str(M2_V1)[0] + "\"" + str(M2_V1)[2:-1] + "\""
                standardized_server_compute_V1 = str(server_compute_V1.digest())[0] + "\"" + str(server_compute_V1.digest())[2:-1] + "\""
                if(standardized_M2_V1 == str(standardized_server_compute_V1)):
                    print("V1 successfully verified")
                    print(f"M2_V1: {standardized_M2_V1}")
                    print(f"computed_V1: {standardized_server_compute_V1}")
                    print()
                    print("Generating Cnext")
                    new_PUF_seed = random.randint(0, 999)
                    C_next = random_inputs(n=64, N=8, seed=new_PUF_seed)
                    print(f"C next: {C_next[0]}...")

                    C_current = random_inputs(n=64, N=8, seed=PUF_seed)
                    #print(f"C: {C_current[0]}...")
                    print("PUF computing R using challenge C")
                    Arbiter = ArbiterPUF(n=64, seed=1)
                    R = Arbiter.eval(C_current)
                    print(f"R: {R}")

                    print("PUF computing R next using C next")
                    Arbiter = ArbiterPUF(n=64, seed=1)
                    R_next = Arbiter.eval(C_next)
                    print(f"R next: {R_next}")

                    print("Computing Verify Key-Hash V2 (SHA-1)")
                    DIDsK_concat = DID + sK
                    DIDsK_concat_bytes = bytes(DIDsK_concat, 'UTF-8')
                    hK_bytes = bytes(str(hK), 'UTF-8')
                    V2 = hmac.new(DIDsK_concat_bytes, hK_bytes, hashlib.sha1)
                    print("V2: " + str(V2.digest()))


                    R_reformat = str(R).replace("-1", "0").replace(" ","").replace("[","").replace("]","")
                    #print(R_reformat)
                    
                    Cnext_reformat = str(C_next).replace("-1", "0").replace(" ","").replace("[","").replace("]",",").replace(" ","")
                    #print(Cnext_reformat)

                    Rnext_reformat = str(R_next).replace("-1", "0").replace(" ","").replace("[","").replace("]","")
                    #print(Rnext_reformat)

                    print("Computing Encrypted Verify Key-Hash EV2")
                    f = Fernet(eK)
                    sKCV1_concat_bytes = V2.digest() + bytes("  ", 'UTF-8') + bytes(sK, 'UTF-8') + bytes("  ", 'UTF-8') + bytes(R_reformat, 'UTF-8') + bytes("  ", 'UTF-8') + bytes(Cnext_reformat, 'UTF-8') + bytes("  ", 'UTF-8') + bytes(Rnext_reformat, 'UTF-8')
                    EV2 = f.encrypt(sKCV1_concat_bytes)
                    print(f"EV2: {EV2[:25]}...")

                    print("Device sending M3: {DID, EV2} to Server")
                    print()
                    print("===================Server======================")
                    print("Load SID")
                    print("SID: " + SID)
                    print()
                    print(f"Finding DID: {DID} in database")

                    # try:
                    server_DID = read_server_csv.loc[read_server_csv['DID'] == DID]['DID'].iloc[0]
                    print(f"DID: {DID} found in database. Now Reading C, R, eK, hK.")
                    print(f"Device Decrypting EV2")
                    server_V3 = f.decrypt(EV2)
                    server_V3 = str(server_V3).split("  ")
                    M3_V2 = str(server_V3[0])+(server_V3[0][1])
                    M3_sK = str(server_V3[1])
                    M3_R = str(server_V3[2])
                    M3_Cnext = str(server_V3[3]).replace("\n","").replace("\\n","").replace("\\","").replace("'","").replace("[","").replace("]","").split(",")[:-2]
                    M3_Rnext = str(server_V3[4])[:-1]
                    print(f"M3 sK: {M3_sK}")
                    print(f"M3 V2: {M3_V2}")
                    print(f"M3 R: {M3_R}")
                    print(f"M3 C next: {M3_Cnext[0]}...")
                    print(f"M3 R next: {M3_Rnext}")
                    print()
                    print(f"Verifying V2")
                    M3_concat = DID + M3_sK
                    M3_concat_bytes = bytes(str(M3_concat), 'UTF-8')
                    server_compute_V2 = hmac.new(M3_concat_bytes, bytes(str(server_hK), 'UTF-8'), hashlib.sha1)
                    standardized_M3_V2 = str(M3_V2)[0] + "\"" + str(M3_V2)[2:-1] + "\""
                    standardized_server_compute_V2 = str(server_compute_V2.digest())[0] + "\"" + str(server_compute_V2.digest())[2:-1] + "\""

                    
                    if (standardized_M3_V2 == standardized_server_compute_V2):
                        print("V2 successfully verified")
                        print(f"M3_V2: {standardized_M3_V2}")
                        print(f"computed_V2: {standardized_server_compute_V2}")
                        print()
                        print("Verifying R")
                        if(M3_R == read_server_csv.loc[read_server_csv['DID'] == DID]['R'].iloc[0]):
                            print("R successfully verified")
                            print(f"M3_R: {M3_R}")
                            print(f"Server_R: {read_server_csv.loc[read_server_csv['DID'] == DID]['R'].iloc[0]}")


                            print("Replacing C R with Cnext Rnext in database")
                            index = read_server_csv.loc[read_server_csv['DID'] == DID].index
                            read_server_csv.drop(index=int(index.values), inplace=True)
                            temp_csv = {'DID': [DID], 'C': [str(C_next).replace("-1", "0").replace(" ","").replace("[","").replace("]",",").replace(" ","")], 'R': [str(R_next).replace("-1", "0").replace(" ","").replace("[","").replace("]","")], 'eK': [eK], 'hK': [hK]}
                            temp_csv_df = pd.DataFrame(data=temp_csv)
                            new_csv = pd.concat([read_server_csv,temp_csv_df])
                            print("Authentication Completed")
                            new_csv.to_csv('setup_server.csv',encoding='utf-8', index=False)

                            print("===================New_Authentication_Details======================")
                            print("DID: " + DID)
                            print("SID: " + SID)
                            print("PUF/Challenge seed: " + str(new_PUF_seed))
                            print("eK: " + str(eK))
                            print("hK: " + str(hK))

                        else:
                            print("R not verified. Aborting...")
                            print(f"M3_R: {M3_R}")
                            print(f"Server_R: {read_server_csv.loc[read_server_csv['DID'] == DID]['R'].iloc[0]}")

                    else:
                        print("V2 not verified. Aborting...")
                        print(f"M3_V2: {standardized_M3_V2}")
                        print(f"computed_V2: {standardized_server_compute_V2}")


                    # except Exception as e:
                    #     print("M3 Stage")
                    #     print(f"DID: {DID} not found in database. Aborting...")


                else:
                    print("V1 not verified. Aborting...")
                    print(f"M2_V1: {M2_V1}")
                    print(f"computed_V1: {standardized_server_compute_V1}")

            else:
                print("SID not verified. Aborting...")

        else:
            print("V0 not verified. Aborting...")
            print(f"M1_V0: {M1_V0}")
            print(f"computed_V0: {str(server_compute_V0.digest())}")



    except:
        print(f"DID: {DID} not found in database. Aborting...")






def auth(DID, SID,PUF_seed, eK, hK):




    read_server_csv = pd.read_csv("setup_server.csv", sep=',', encoding="utf-8")

    print("============Auth Phrase Started================")
    print()
    print("==============Device_Properties================")
    print("DID: " + DID)
    print("SID: " + SID)
    print("PUF seed: " + str(PUF_seed))
    print("eK: " + str(eK))
    print("hK: " + str(hK))
    print("===============================================")
    print()
    print("===================Device======================")
    print("Generating Session Key sK")
    sK = "".join(np.random.choice(list(string.digits))for i in range(8))
    print("sK: " + sK)
    print()
    print("Computing Verify Key-Hash V0 (SHA-1)")
    DIDsK_concat = DID + sK
    DIDsK_concat_bytes = bytes(DIDsK_concat, 'UTF-8')
    hK_bytes = bytes(str(hK), 'UTF-8')
    V0 = hmac.new(DIDsK_concat_bytes, hK_bytes, hashlib.sha1)
    print("V0: " + str(V0.digest()))
    print()
    print("Computing Encrypted Verify Key-Hash EV0")
    f = Fernet(eK)
    sKV0_concat_bytes = V0.digest() + bytes("  ", 'UTF-8') + bytes(sK, 'UTF-8')
    EV0 = f.encrypt(sKV0_concat_bytes)
    print("EV0: " + str(EV0))
    print()
    print("Device sending M1: {DID, EV0} to Server")
    print("===============================================")
    print()
    print("===================Server======================")
    print("Load SID")
    print("SID: " + SID)
    print()
    print(f"Finding DID: {DID} in database")

    read_server_csv = pd.read_csv("setup_server.csv", sep=',', encoding="utf-8")


    try:

        server_DID = read_server_csv.loc[read_server_csv['DID'] == DID]['DID'].iloc[0]
        print(f"DID: {DID} found in database. Now Reading C, R, eK, hK.")
        server_C = read_server_csv.loc[read_server_csv['DID'] == DID]['C'].iloc[0]
        server_R = read_server_csv.loc[read_server_csv['DID'] == DID]['R'].iloc[0]
        server_eK = read_server_csv.loc[read_server_csv['DID'] == DID]['eK'].iloc[0]
        server_hK = read_server_csv.loc[read_server_csv['DID'] == DID]['hK'].iloc[0]
        print(f"C: {server_C[:20]}...")
        print(f"R: {server_R}")
        print(f"eK: {server_eK}")
        print(f"hK: {server_hK}")
        server_sK_v0 = f.decrypt(EV0)

        server_sK_v0 = str(server_sK_v0).split("  ")



        print(f"Server Decrypting EV0")
        M1_V0 = str(server_sK_v0[0])+(server_sK_v0[0][1])
        M1_sK = str(server_sK_v0[1][:-1])
        print(f"M1 sK: {M1_sK}")
        print(f"M1 V0: {M1_V0}")
        M1_DID_concat_sK = DID + M1_sK
        M1_DID_concat_sK_bytes = bytes(str(M1_DID_concat_sK), 'UTF-8')
        server_compute_V0 = hmac.new(M1_DID_concat_sK_bytes, bytes(str(server_hK), 'UTF-8'), hashlib.sha1)
        print()
        print(f"Verifying V0")
        if(M1_V0 == str(server_compute_V0.digest())):
            print("V0 successfully verified")
            print(f"M1_V0: {M1_V0}")
            print(f"computed_V0: {str(server_compute_V0.digest())}")
            print()
            print("Computing Verify Key-Hash V1 (SHA-1)")
            SIDsK_concat = SID + sK
            SIDsK_concat_bytes = bytes(SIDsK_concat, 'UTF-8')
            hK_bytes = bytes(str(hK), 'UTF-8')
            V1 = hmac.new(SIDsK_concat_bytes, hK_bytes, hashlib.sha1)
            print("V1: " + str(V1.digest()))
            print()
            print("Computing Encrypted Verify Key-Hash EV1")
            server_c_arr = server_C.split(",")
            temp = []
            for row in server_c_arr:
                temp.append(row)
            C1 = list(filter(None, temp))
            C1_str = str(C1)

            f = Fernet(eK)
            sKCV1_concat_bytes = V1.digest() + bytes("  ", 'UTF-8') + bytes(sK, 'UTF-8') + bytes("  ", 'UTF-8') + bytes(C1_str, 'UTF-8')
            EV1 = f.encrypt(sKCV1_concat_bytes)
            print(f"EV1: {EV1[:50]}...")
            print()
            print("Server sending M2: {SID, EV1} to Device")
            print()
            print("===================Device======================")
            print(f"Finding SID: {SID} in Secure-NVM")
            if(SID == "Demo_Server"):
                print("SID verified")
                print("Reading eK, hK from secure-NVM")
                print(f"eK: {eK}")
                print(f"hK: {hK}")
                print()
                print(f"Device Decrypting EV1")
                device_sKCV1 = f.decrypt(EV1)
                device_sKCV1 = str(device_sKCV1).split("  ")
                M2_V1 = str(device_sKCV1[0])+(device_sKCV1[0][1])
                M2_sK = str(device_sKCV1[1])
                M2_C = str(device_sKCV1[2][:-1])
                print(f"M2 sK: {M2_sK}")
                print(f"M2 V1: {M2_V1}")
                M2_C_arr = M2_C.replace("\n","").replace("\\n","").replace("\\","").replace("'","").replace("[","").replace("]","").split(",")
                print(f"M2 C: {M2_C_arr[0]}...")
                print()
                print(f"Verifying V1")
                M2_SID_sK_concat = SID + M2_sK
                M2_SID_sK_concat_bytes = bytes(str(M2_SID_sK_concat), 'UTF-8')
                server_compute_V1 = hmac.new(M2_SID_sK_concat_bytes, bytes(str(server_hK), 'UTF-8'), hashlib.sha1)
                standardized_M2_V1 = str(M2_V1)[0] + "\"" + str(M2_V1)[2:-1] + "\""
                standardized_server_compute_V1 = str(server_compute_V1.digest())[0] + "\"" + str(server_compute_V1.digest())[2:-1] + "\""
                if(standardized_M2_V1 == str(standardized_server_compute_V1)):
                    print("V1 successfully verified")
                    print(f"M2_V1: {standardized_M2_V1}")
                    print(f"computed_V1: {standardized_server_compute_V1}")
                    print()
                    print("Generating Cnext")
                    new_PUF_seed = random.randint(0, 999)
                    C_next = random_inputs(n=64, N=8, seed=new_PUF_seed)
                    print(f"C next: {C_next[0]}...")

                    C_current = random_inputs(n=64, N=8, seed=PUF_seed)
                    #print(f"C: {C_current[0]}...")
                    print("PUF computing R using challenge C")
                    Arbiter = ArbiterPUF(n=64, seed=1)
                    R = Arbiter.eval(C_current)
                    print(f"R: {R}")

                    print("PUF computing R next using C next")
                    Arbiter = ArbiterPUF(n=64, seed=1)
                    R_next = Arbiter.eval(C_next)
                    print(f"R next: {R_next}")

                    print("Computing Verify Key-Hash V2 (SHA-1)")
                    DIDsK_concat = DID + sK
                    DIDsK_concat_bytes = bytes(DIDsK_concat, 'UTF-8')
                    hK_bytes = bytes(str(hK), 'UTF-8')
                    V2 = hmac.new(DIDsK_concat_bytes, hK_bytes, hashlib.sha1)
                    print("V2: " + str(V2.digest()))


                    R_reformat = str(R).replace("-1", "0").replace(" ","").replace("[","").replace("]","")
                    #print(R_reformat)
                    
                    Cnext_reformat = str(C_next).replace("-1", "0").replace(" ","").replace("[","").replace("]",",").replace(" ","")
                    #print(Cnext_reformat)

                    Rnext_reformat = str(R_next).replace("-1", "0").replace(" ","").replace("[","").replace("]","")
                    #print(Rnext_reformat)

                    print("Computing Encrypted Verify Key-Hash EV2")
                    f = Fernet(eK)
                    sKCV1_concat_bytes = V2.digest() + bytes("  ", 'UTF-8') + bytes(sK, 'UTF-8') + bytes("  ", 'UTF-8') + bytes(R_reformat, 'UTF-8') + bytes("  ", 'UTF-8') + bytes(Cnext_reformat, 'UTF-8') + bytes("  ", 'UTF-8') + bytes(Rnext_reformat, 'UTF-8')
                    EV2 = f.encrypt(sKCV1_concat_bytes)
                    print(f"EV2: {EV2[:25]}...")

                    print("Device sending M3: {DID, EV2} to Server")
                    print()
                    print("===================Server======================")
                    print("Load SID")
                    print("SID: " + SID)
                    print()
                    print(f"Finding DID: {DID} in database")

                    # try:
                    server_DID = read_server_csv.loc[read_server_csv['DID'] == DID]['DID'].iloc[0]
                    print(f"DID: {DID} found in database. Now Reading C, R, eK, hK.")
                    print(f"Device Decrypting EV2")
                    server_V3 = f.decrypt(EV2)
                    server_V3 = str(server_V3).split("  ")
                    M3_V2 = str(server_V3[0])+(server_V3[0][1])
                    M3_sK = str(server_V3[1])
                    M3_R = str(server_V3[2])
                    M3_Cnext = str(server_V3[3]).replace("\n","").replace("\\n","").replace("\\","").replace("'","").replace("[","").replace("]","").split(",")[:-2]
                    M3_Rnext = str(server_V3[4])[:-1]
                    print(f"M3 sK: {M3_sK}")
                    print(f"M3 V2: {M3_V2}")
                    print(f"M3 R: {M3_R}")
                    print(f"M3 C next: {M3_Cnext[0]}...")
                    print(f"M3 R next: {M3_Rnext}")
                    print()
                    print(f"Verifying V2")
                    M3_concat = DID + M3_sK
                    M3_concat_bytes = bytes(str(M3_concat), 'UTF-8')
                    server_compute_V2 = hmac.new(M3_concat_bytes, bytes(str(server_hK), 'UTF-8'), hashlib.sha1)
                    standardized_M3_V2 = str(M3_V2)[0] + "\"" + str(M3_V2)[2:-1] + "\""
                    standardized_server_compute_V2 = str(server_compute_V2.digest())[0] + "\"" + str(server_compute_V2.digest())[2:-1] + "\""

                    
                    if (standardized_M3_V2 == standardized_server_compute_V2):
                        print("V2 successfully verified")
                        print(f"M3_V2: {standardized_M3_V2}")
                        print(f"computed_V2: {standardized_server_compute_V2}")
                        print()
                        print("Verifying R")
                        if(M3_R == read_server_csv.loc[read_server_csv['DID'] == DID]['R'].iloc[0]):
                            print("R successfully verified")
                            print(f"M3_R: {M3_R}")
                            print(f"Server_R: {read_server_csv.loc[read_server_csv['DID'] == DID]['R'].iloc[0]}")


                            print("Replacing C R with Cnext Rnext in database")
                            index = read_server_csv.loc[read_server_csv['DID'] == DID].index
                            read_server_csv.drop(index=int(index.values), inplace=True)
                            temp_csv = {'DID': [DID], 'C': [str(C_next).replace("-1", "0").replace(" ","").replace("[","").replace("]",",").replace(" ","")], 'R': [str(R_next).replace("-1", "0").replace(" ","").replace("[","").replace("]","")], 'eK': [eK], 'hK': [hK]}
                            temp_csv_df = pd.DataFrame(data=temp_csv)
                            new_csv = pd.concat([read_server_csv,temp_csv_df])
                            print("Authentication Completed")
                            new_csv.to_csv('setup_server.csv',encoding='utf-8', index=False)

                            print("===================New_Authentication_Details======================")
                            print("DID: " + DID)
                            print("SID: " + SID)
                            print("PUF/Challenge seed: " + str(new_PUF_seed))
                            print("eK: " + str(eK))
                            print("hK: " + str(hK))

                        else:
                            print("R not verified. Aborting...")
                            print(f"M3_R: {M3_R}")
                            print(f"Server_R: {read_server_csv.loc[read_server_csv['DID'] == DID]['R'].iloc[0]}")

                    else:
                        print("V2 not verified. Aborting...")
                        print(f"M3_V2: {standardized_M3_V2}")
                        print(f"computed_V2: {standardized_server_compute_V2}")


                    # except Exception as e:
                    #     print("M3 Stage")
                    #     print(f"DID: {DID} not found in database. Aborting...")


                else:
                    print("V1 not verified. Aborting...")
                    print(f"M2_V1: {M2_V1}")
                    print(f"computed_V1: {standardized_server_compute_V1}")

            else:
                print("SID not verified. Aborting...")

        else:
            print("V0 not verified. Aborting...")
            print(f"M1_V0: {M1_V0}")
            print(f"computed_V0: {str(server_compute_V0.digest())}")



    except:
        print(f"DID: {DID} not found in database. Aborting...")


