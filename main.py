# This file contains the code which will be interacting with the indy-pool

import asyncio
import json, time
from os.path import dirname
from indy import pool,wallet,did,ledger,anoncreds,blob_storage
from indy.error import ErrorCode, IndyError

async def create_wallet(identity):
    print("creating the wallet".format(identity['name']))
    try:# will use the API to create the wallet
        await wallet.create_wallet(identity['wallet_config'], identity['wallet_credentials']) 
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass 
        
    identity['wallet'] = await wallet.open_wallet(identity['wallet_config'], identity['wallet_credentials'])


async def getting_verinym(from_,to):

    # first creating the wallet for government
    await create_wallet(to)

    (to['did'], to['key']) = await did.create_and_store_my_did(to['wallet'],"{}")

    from_['info'] = {
        'did': to['did'],
        'verkey': to['key'],
        'role': to['role'] or None
    }

    # send_nym id the actual tx which indy supports
    await send_nym(from_['pool'], from_['wallet'], from_['did'],from_['info']['did'], from_['info']['verkey'], from_['info']['role'])

async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    # while registering the did we need to send a nym tx
    nym_request = await ledger.build_nym_request(_did,new_did,new_key,None,role)
    print(nym_request)
    # This is the API call
    await ledger.sign_and_submit_request(pool_handle,wallet_handle,_did,nym_request)

async def ensure_previous_request_applied(pool_handle,checker_request,checker):
    for _ in range(3):
        response = json.loads(await ledger.submit_request(pool_handle,checker_request))
        try:
            if checker(response):
                return json.dumps(response)
        except TypeError:
            pass
        time.sleep(5)

# takes the cred if as argument and fetched the defininton from the indy ledger
async def get_cred_def(pool_handle,_did,cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did,cred_def_id)
    get_cred_def_response = await ensure_previous_request_applied(pool_handle,get_cred_def_request,lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']

# it will take input the required presentations request and then fetch requied schemas
async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp_from=None,
                                          timestamp_to=None):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.", item['schema_id'])
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Create Revocations States
            print("\"{}\" -> Get Revocation Registry Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_def_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            print("\"{}\" -> Get Revocation Registry Delta from Ledger".format(actor))
            if not timestamp_to: timestamp_to = int(time.time())
            get_revoc_reg_delta_request = \
                await ledger.build_get_revoc_reg_delta_request(_did, item['rev_reg_id'], timestamp_from, timestamp_to)
            get_revoc_reg_delta_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_delta_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_delta_json, t) = \
                await ledger.parse_get_revoc_reg_delta_response(get_revoc_reg_delta_response)

            tails_reader_config = json.dumps(
                {'base_dir': dirname(json.loads(revoc_reg_def_json)['value']['tailsLocation']),
                 'uri_pattern': ''})
            blob_storage_reader_cfg_handle = await blob_storage.open_reader('default', tails_reader_config)

            print('%s - Create Revocation State', actor)
            rev_state_json = \
                await anoncreds.create_revocation_state(blob_storage_reader_cfg_handle, revoc_reg_def_json,
                                                        revoc_reg_delta_json, t, item['cred_rev_id'])
            rev_states[rev_reg_id] = {t: json.loads(rev_state_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)

async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ensure_previous_request_applied(
        pool_handle, get_schema_request, lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_schema_response(get_schema_response)

async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp=None):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Get Revocation Definitions and Revocation Registries
            print("\"{}\" -> Get Revocation Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_def_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            print("\"{}\" -> Get Revocation Registry from Ledger".format(actor))
            if not timestamp: timestamp = item['timestamp']
            get_revoc_reg_request = \
                await ledger.build_get_revoc_reg_request(_did, item['rev_reg_id'], timestamp)
            get_revoc_reg_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, rev_reg_json, timestamp2) = await ledger.parse_get_revoc_reg_response(get_revoc_reg_response)

            rev_regs[rev_reg_id] = {timestamp2: json.loads(rev_reg_json)}
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def run():

    print("testing the functin only")

    print("STEP 1: to connect to the indy pool")
    print("\n\n\n----------------------------------")

    # creating pool definintion
     
    pool_ = {
        "name": "FirstPool"
    }

    print("open pool ledger: {}".format(pool_["name"]))
    pool_['genesis_txn_path'] = "pool1.txn"
    
    pool_['config']  = json.dumps({"genesis_txn": str(pool_['genesis_txn_path'])})
    print(pool_)

    # Connecting the pool
    await pool.set_protocol_version(2) #This is a indy function

    try:
        await pool.create_pool_ledger_config(pool_['name'],pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass 
        else:
            print(ex)
            raise ex
    # will open the pool
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'],None)

    print("this is the pool handle: {}".format({pool_['handle']}))

    print("STEP 2: Configuring the stewards")
    print("\n\n\n----------------------------------")

    # The pool we started has four nodes and all of these four nodes are stewards
    # These stewards are run using a pre-defined seed value
    # using the seed value the privated key will be generated which will help in controlling the stewards

    steward = {
        'name': "Soverign steward",
        'wallet_config' : json.dumps({'id':'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }

    print("This is steward:{}".format(steward))

    await create_wallet(steward)

    print(steward["wallet"])

    steward["did_info"] = json.dumps({'seed':steward['seed']})
    print(steward["did_info"])

    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'],steward['did_info'])

    print("STEP 3: Register DID for government")
    print("\n\n\n----------------------------------")

    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id':'government_wallet'}),
        'wallet_credentials': json.dumps({'key':'government_wallet_key'}),
        'pool': pool_['handle'],
        'role':'TRUST_ANCHOR'
    }
    # registering the verinym for government using the steward
    await getting_verinym(steward,government)

    print("STEP 4: register the did for university and company")
    print("\n\n\n----------------------------------")

    print("University getting the verinym")
    print("\n\n\n----------------------------------")

    theUniversity = {
        'name': 'theUniversity',
        'wallet_config': json.dumps({'id':'theUniversity_wallet'}),
        'wallet_credentials': json.dumps({'key':'theUniversity_wallet_key'}),
        'pool': pool_['handle'],
        'role':'TRUST_ANCHOR'
    }

    await getting_verinym(steward,theUniversity)

    print("Company getting the verinym")
    print("\n\n\n----------------------------------")

    theCompany = {
        'name': 'theCompany',
        'wallet_config': json.dumps({'id':'theCompany_wallet'}),
        'wallet_credentials': json.dumps({'key':'theCompany_wallet_key'}),
        'pool': pool_['handle'],
        'role':'TRUST_ANCHOR'
    }

    await getting_verinym(steward,theCompany)

    print("\n\n\n----------------------------------")
    print("STEP 5: Government would be creating a credential schema for Transcript and register it in the indy ledger")
    print("\n\n\n----------------------------------")

    # Government creatingn a transcript schema
    # Transcript schema cannot be deleted it can be updated by giving the new version no: a new one can be created with different version


    transcript = {
        'name': 'Transcript',
        'version': '1.2',
        'attributes': ['first_name','last_name','degree','status','year','average','ssn']
    }

    # Using the anoncreds API to register the transcript schema
    (government['transcript_schema_id'], government['transcript_schema']) = await anoncreds.issuer_create_schema(government['did'],
                                                                                                                transcript['name'],
                                                                                                                transcript['version'],
                                                                                                                json.dumps(transcript['attributes']))



    print(government['transcript_schema'])
    transcript_schema_id = government['transcript_schema_id']

    # Now we will have the add the registered schema to the ledger for that we will sign and submit the tx

    print("\n----------------------------------")
    print("Schema to ledger")
    print("\n----------------------------------")

    schema_request = await ledger.build_schema_request(government['did'],government['transcript_schema'])
    await ledger.sign_and_submit_request(government['pool'],government['wallet'],government['did'],schema_request)

    print("\n----------------------------------")
    print("STEP 6: University will create the credentail definition for transcript using which it will transfer it to Alice")
    print("\n----------------------------------")

    # Getting the schema from the ledger and then it will used to form the transcript definition

    get_schema_request = await ledger.build_get_schema_request(theUniversity['did'],transcript_schema_id)
    # this will check if artifact is present in the ledger or not
    get_schema_response = await ensure_previous_request_applied(theUniversity['pool'],get_schema_request,lambda response:response['result']['data']is not None)
    (theUniversity['transcription_schema_id'],theUniversity['transcript_schema']) = await ledger.parse_get_schema_response(get_schema_response)

    # transcript credentail definition
    print("\n----------------------------------")
    print("the transcript credential definition")
    print("\n----------------------------------")

    transcript_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }

    (theUniversity['transcript_cred_def_id'], theUniversity['transcript_cred_def']) = await anoncreds.issuer_create_and_store_credential_def(theUniversity['wallet'],
                                                                                                                                            theUniversity['did'],
                                                                                                                                            theUniversity['transcript_schema'],
                                                                                                                                            transcript_cred_def['tag'],
                                                                                                                                            transcript_cred_def['type'],
                                                                                                                                            json.dumps(transcript_cred_def['config']))
    print("sending the credential definition  to the ledger") 

    cred_def_request = await ledger.build_cred_def_request(theUniversity['did'],theUniversity['transcript_cred_def'])
    # after creating the request we will sign and submit it
    await ledger.sign_and_submit_request(theUniversity['pool'],theUniversity['wallet'],theUniversity['did'],cred_def_request)
    print("\n ",theUniversity['transcript_cred_def_id'])

    print("\n----------------------------------")
    print("STEP 7: University issues transcript to Alice")
    print("\n----------------------------------")

    # Alice will request the credential and the university will grant the credentials to Alice: To and fro request process

    print("\n----")
    print("Setting Alice wallet")
    print("\n----")


    # we will set up alice wallet and store DID in his wallet

    alice = {
        'name': 'Alice',
        'wallet_config': json.dumps({'id':'alice_wallet'}),
        'wallet_credentials':json.dumps({'key':'alice_wallet_key'}),
        'pool': pool_['handle'],
    }


    # This will create Alice wallet and store the did in the wallet
    await create_wallet(alice)
    (alice['did'],alice['key']) = await did.create_and_store_my_did(alice['wallet'],"{}")

    print("\n")
    print("University will create transcript credential and send offer to Alice")

    #based on this offer Alice will send the request to university
    # stage 1 - offer, stage 2- request

    theUniversity['transcript_cred_offer'] = await anoncreds.issuer_create_credential_offer(theUniversity['wallet'],theUniversity['transcript_cred_def_id'])

    # in real word the offer will be send to Alice over the network, here we are just directly assigning the offer to Alice

    alice['transcript_cred_offer'] = theUniversity['transcript_cred_offer']
    print("\n")
    print("Alice offer")
    print("\n")
    print(alice['transcript_cred_offer'])

    print(" Alice prepares the transcript credential request")
    print("\n")

    transcript_cred_offer_object = json.loads(alice['transcript_cred_offer'])
    alice['transcript_schema_id'] = transcript_cred_offer_object['schema_id'];
    alice['transcript_cred_def_id'] = transcript_cred_offer_object['cred_def_id'];

    # Alice will prepare a Master secret in wallet in order to create a request for the creds
    # Master secret ensures that the  issuer will be issuing only one cred to Alice and it will be unique
    print("\n")
    print("Alice create a master key")
    print("\n")
    alice['master_secret_id'] = await anoncreds.prover_create_master_secret(alice['wallet'],None)

    # Using the master secret the issuer will generate the the creds such that without the master secret no one can use it
    print("\n")
    print("Alice getting the cred definintion from the ledger")
    print("\n")
    # for making the request  Alice need to get the cred definition from the ledger
    (alice['theUniversity_transcript_cred_def_id'], alice['theUniversity_transcript_cred_def']) = await get_cred_def(alice['pool'],
                                                                                                                    alice['did'],
                                                                                                                    alice['transcript_cred_def_id'])
    print("\n")
    print("Alice will be able to create a tx request")
    print("\n")
    # this is just the request creation, after this it will be sent to university
    (alice['transcript_cred_request'],alice['transcript_cred_request_metadata']) = await anoncreds.prover_create_credential_req(
                                                                                                                                alice['wallet'],
                                                                                                                                alice['did'],
                                                                                                                                alice['transcript_cred_offer'],
                                                                                                                                alice['theUniversity_transcript_cred_def'],
                                                                                                                                alice['master_secret_id'])

    # NOw this transcript request need to go from alice to the university, this will happend over the network but we are not doing it here
    theUniversity['transcript_cred_request'] = alice['transcript_cred_request']# using the transcript_cred_req university can now start issuing the creds

    # now university can issue the transcript creds to Alice
    print("\n")
    print("now university can issue the transcript creds to Alice")
    print("\n")
    #indy does not specify any particular encoding scheme, so user can use any
    theUniversity['alice_transcript_cred_values'] = json.dumps({
        
        "first_name": {"raw": "Alice", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
        "degree": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
        "status": {"raw": "graduated", "encoded": "2213454313412354"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "year": {"raw": "2015", "encoded": "2015"},
        "average": {"raw": "5", "encoded": "5"}
    
    })

    theUniversity['transcript_cred'],_,_ = await anoncreds.issuer_create_credential(
                                                                                theUniversity['wallet'],
                                                                                theUniversity['transcript_cred_offer'],
                                                                                theUniversity['transcript_cred_request'],
                                                                                theUniversity['alice_transcript_cred_values'],
                                                                                None,None
                                                                                )
    
    print("\n")
    print("University sends transcript creds to alice")
    print("\n")
    print(theUniversity['transcript_cred'])

    # now this transcript creds need to be transferred to alice over the network but here we will not do that
    alice['transcript_cred'] = theUniversity['transcript_cred']
     
    # Now alice will store the creds into its own wallet

    _,alice['transcript_cred_def'] = await get_cred_def(alice['pool'],alice['did'],alice['transcript_cred_def_id'])
    await anoncreds.prover_store_credential(alice['wallet'],None,alice['transcript_cred_request_metadata'],alice['transcript_cred'],alice['transcript_cred_def'],None)
    print("\n")
    print("Alice transcript cred definition")
    print("\n")
    print(alice['transcript_cred_def'])


    # issues has shared the crdentials withe alice now alice will make the verifiable presentations
    print("\n")
    print("Alice will make the verifiable presentations to the company")
    print("\n")
    # this job request is beign created by the company having certian attributes which are required for the application
    # requested attr are will be prepared by alice 
    # restricted atte shold be shared through verifiable channel
    nonce = await anoncreds.generate_nonce()
    theCompany['job_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree',
                'restrictions': [{'cred_def_id': theUniversity['transcript_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': theUniversity['transcript_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': theUniversity['transcript_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'average',
                'p_type': '>=',
                'p_value': 4,
                'restrictions': [{'cred_def_id': theUniversity['transcript_cred_def_id']}]
            }
        }
    })

    print("\ncompany will sedn the job application requeset to alice\n")

    # over network but here we are doing direclty
    alice['job_application_proof_request'] = theCompany['job_application_proof_request']

    # using this proof request Alice can generate the presentation
    # before creating the presentatin Alice wll have to get hold of creds
    
    print("\nGet creds for proof request\n")

    search_for_job_application_proof_request = await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],alice['job_application_proof_request'], None)
    
    # all the attributes will be coming fromt he same transacript cred issued by university 

    print("\nSearch for job application proof request\n")
    # function get_credential_for_referent will find the creds required for satisfying attr
    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

    #predicate(it includes a condition) is a particular value which can be presented as a ZK proof
    
    # now after getting the creds they can be used to form the proof

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)#first we will close the search for proof request
    #mapping the creds to different referent and predicates
    alice['creds_for_job_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_predicate1['referent']: cred_for_predicate1}

    #fetch more artifacts from ledger which will be required to create the presentations
    print(alice['creds_for_job_application_proof'])
    #alice would required the schema for this job application, this function will fetch required schemas
    # function also fetches the credential definition and revocatino list if any
    alice['schemas_for_job_application'], alice['cred_defs_for_job_application'],alice['revoc_states_for_job_application'] = await prover_get_entities_from_ledger(alice['pool'], alice['did'],
                                              alice['creds_for_job_application_proof'], alice['name'])

    
    print("\njob application presentaion \n")
    # attr 1,2,6 are having no restrictions. 3,4,5 as restrictino that it should come froma a particular credential
    # in presentation actual value will be revealed
    alice['job_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Alice',
            'attr2_referent': 'Garcia',
            'attr6_referent': '123-45-6789'
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    #presentation from alice which will be validated by the company
    alice['job_application_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['job_application_proof_request'],
                                            alice['job_application_requested_creds'], alice['master_secret_id'],
                                            alice['schemas_for_job_application'],
                                            alice['cred_defs_for_job_application'],
                                            alice['revoc_states_for_job_application'])
    print(alice['job_application_proof'])

    # sendig the applicatin to the company
    print("\nProof to theCompany\n")
    # Over Network
    theCompany['job_application_proof'] = alice['job_application_proof']

    print("\nLast step: now company will validate the submission\n")


     # Validating the verifiable presentation
    job_application_proof_object = json.loads(theCompany['job_application_proof'])

    theCompany['schemas_for_job_application'], theCompany['cred_defs_for_job_application'], \
    theCompany['revoc_ref_defs_for_job_application'], theCompany['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(theCompany['pool'], theCompany['did'],
                                                job_application_proof_object['identifiers'], theCompany['name'])



    #this will validate all the proofs restricted and unrestricted
    print("\"theCompany\" -> Verify \"Job-Application\" Proof from Alice")
    assert 'Bachelor of Science, Marketing' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'graduated' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'Alice' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Garcia' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(theCompany['job_application_proof_request'], theCompany['job_application_proof'],
                                                 theCompany['schemas_for_job_application'],
                                                 theCompany['cred_defs_for_job_application'],
                                                 theCompany['revoc_ref_defs_for_job_application'],
                                                 theCompany['revoc_regs_for_job_application'])



    

loop = asyncio.get_event_loop()
loop.run_until_complete(run())
# asyncio.run(run())
