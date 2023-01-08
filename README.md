# HyperledgerIndyAssignment

This is a basic project which showcases the Issuer,Holder,Verifier scenario. Follow below steps to run the project.

--Clone Indy-sdk(git clone https://github.com/hyperledger/indy-sdk.git)
--Cd indy-sdk
--Build and run indy  pool docker image (Commands given below)
  --docker build -f ci/indy-pool.dockerfile -t indy_pool .(This will create a docker image with name indy_pool)
  --docker run -itd -p 9701-9708:9701-9708 indy_pool (On running the created image, it will create a pool of 4 indy nodes).
--Install python3 wrapper to interact with the Indy pool(pip install python3-indy)

After doing all this, clone this repo in the same python environment where you have installed python3-indy. Then run this command - python3 main.py.
You will start seeing the output of the program.
