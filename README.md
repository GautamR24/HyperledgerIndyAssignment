
# HyperledgerIndyAssignment

## Start

This is a basic project which showcases the Issuer,Holder,Verifier scenario. Follow below steps to run the project.

## Steps to follow

1)Clone Indy-sdk(git clone https://github.com/hyperledger/indy-sdk.git)  
2)Cd indy-sdk  
3)Build and run indy pool docker image (Commands given below)  
4)docker build -f ci/indy-pool.dockerfile -t indy_pool .(This will create a docker image with name indy_pool)  
5)docker run -itd -p 9701-9708:9701-9708 indy_pool (On running the created image, it will create a pool of 4 indy nodes).  
6)Install python3 wrapper to interact with the Indy pool(pip install python3-indy)


## Final
After doing all this, clone this repo in the same python environment where you have installed python3-indy. Then run this command - python3 main.py. You will start seeing the output of the program.
