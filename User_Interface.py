import Setup_Protocol_Simulation
import Auth_Protocol_Simulation
import V1_attack
import V2_attack
import RNXORPUF_Simulation

DID = "Device_ITJ7JH9M"
SID = "Demo_Server"
PUF_seed = 991
eK = b'gSskwJXCh45DgSQBtse3-gupK1XSy2-mLTTGNlXTBrk='
hK = 77492606

#stage = input("Enter Stage: ")
mode = "V2_attack"




if __name__ == "__main__":

    if(mode == "setup"):
        Setup_Protocol_Simulation.setup()

    if(mode == "auth"):
        Auth_Protocol_Simulation.auth(DID, SID,PUF_seed, eK, hK)

    if(mode == "V1_attack"):
        V1_attack.V1_injection(DID, SID,PUF_seed, eK, hK)

    if(mode == "V2_attack"):
        V2_attack.V2_injection(DID, SID,PUF_seed, eK, hK)

    if(mode == "PUF"):
        RNXORPUF_Simulation.RNXORPUF_sim(5)

    