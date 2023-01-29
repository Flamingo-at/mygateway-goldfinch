import requests
import cloudscraper

from web3.auto import w3
from loguru import logger
from eth_account.messages import encode_defunct


def sending_captcha():
    try:
        response = requests.get(f'http://api.captcha.guru/in.php?key={user_key}&method=userrecaptcha \
            &googlekey=6LdcH1ojAAAAALctZPJkHJMiveW03yFr_vRvZXg6&pageurl=https://www.mygateway.xyz/&softguru=129939')
        data = response.text
        if 'ERROR' in data:
            logger.error(data)
            return(sending_captcha())
        id = data[3:]
        return(solving_captcha(id))
    except:
        raise Exception()


def solving_captcha(id: str):
    for i in range(100):
        try:
            response = requests.get(
                f'http://api.captcha.guru/res.php?key={user_key}&action=get&id={id}')
            data = response.text
            if 'ERROR' in data:
                logger.error(data)
                raise Exception()
            elif 'OK' in data:
                return(data[3:])
            return(solving_captcha(id))
        except:
            raise Exception()
    raise Exception()


def create_email():
    try:
        email = requests.get(
            "https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1").json()[0]
        return email
    except:
        logger.error('Failed create email')
        raise Exception


def create_wallet():
    account = w3.eth.account.create()
    return(str(account.address), str(account.privateKey.hex()))


def create_signature(private_key: str, nonce: str):
    message = encode_defunct(text=nonce)
    signed_message = w3.eth.account.sign_message(message, private_key)
    return(signed_message.signature.hex())


def get_auth_csrf_token(scraper: cloudscraper):
    with scraper.get('https://www.mygateway.xyz/api/auth/session') as response:
        headers = str(response.headers)
        auth_csrf_token = headers[headers.find(
            '__Host-next'):headers.find(';', headers.find('__Host-next'))]
        if auth_csrf_token == '':
            return(get_auth_csrf_token(scraper))
    return(auth_csrf_token)


def task(scraper: cloudscraper, task_id_1: str, task_id_2: str, gateId: str, answer: list):
    try:
        scraper.post('https://api.mygateway.xyz/v1/graphql',
                     json={
                         "query": "mutation complete_task($task_id: uuid!, $info: json) {\n  verify_key(input: {task_id: $task_id, info: $info}) {\n    task_info\n  }\n}",
                         "variables": {
                             "task_id": task_id_1,
                                        "info": {}
                         },
                         "operationName": "complete_task"
                     })

        scraper.post('https://api.mygateway.xyz/v1/graphql',
                     json={
                         "query": "mutation complete_task($task_id: uuid!, $info: json) {\n  verify_key(input: {task_id: $task_id, info: $info}) {\n    task_info\n  }\n}",
                         "variables": {
                             "task_id": task_id_2,
                                        "info": {
                                            "questions": answer
                                        }
                         },
                         "operationName": "complete_task"
                     })

        captcha = sending_captcha()
        id = scraper.post('https://api.mygateway.xyz/v1/graphql',
                          json={
                              "query": "mutation complete_gate($gateId: uuid!, $recaptcha: String!) {\n  complete_gate(gate_id: $gateId, recaptcha: $recaptcha)\n}",
                              "variables": {
                                  "gateId": gateId,
                                  "recaptcha": captcha
                              },
                              "operationName": "complete_gate"
                          }).json()['data']['complete_gate']['credential']['id']
    except:
        raise Exception()

    return(id)


def mint_nft(scraper: cloudscraper, id: str):
    try:
        transaction_hash = scraper.post('https://api.mygateway.xyz/v1/graphql',
                                        json={
                                            "query": "mutation mint_credential($id: uuid!) {\n  mint_credential(credential_id: $id) {\n    status\n    message\n    info {\n      transaction_hash\n      chain_id\n      wallet\n    }\n  }\n}",
                                            "variables": {
                                                "id": id
                                            },
                                            "operationName": "mint_credential"
                                        }).json()['data']['mint_credential']['info']['transaction_hash']
    except:
        raise Exception()


def main():
    while True:
        try:
            with cloudscraper.CloudScraper() as scraper:

                auth_csrf_token = get_auth_csrf_token(scraper)

                address, private_key = create_wallet()

                logger.info('Connection wallet')
                nonce = scraper.post('https://api.mygateway.xyz/v1/graphql',
                                     json={
                                         "query": "query get_nonce($wallet: String!) {\n  get_nonce(wallet: $wallet) {\n    nonce\n  }\n}",
                                         "variables": {
                                             "wallet": address
                                         },
                                         "operationName": "get_nonce"
                                     }).json()['data']['get_nonce']['nonce']

                scraper.headers.update({'cookie': f'{auth_csrf_token}; __Secure-next-auth.callback-url=https%3A%2F%2Fwww.mygateway.xyz'})

                csrfToken = scraper.get('https://www.mygateway.xyz/api/auth/csrf').json()['csrfToken']

                logger.info('Verification wallet')
                signature = create_signature(
                    private_key, f'Welcome to Gateway!\n\nPlease sign this message for access: {nonce}')
                response = scraper.post('https://www.mygateway.xyz/api/auth/callback/credentials?',
                                        data={
                                            'redirect': 'false',
                                            'wallet': address,
                                            'signature': signature,
                                            'csrfToken': csrfToken,
                                            'callbackUrl': 'https://www.mygateway.xyz/dao/goldfinch',
                                            'json': 'true'
                                        })
                headers = str(response.headers)
                auth_session_token = headers[headers.find('__Secure-next-auth.session'):headers.find(';', headers.find('__Secure-next-auth.session'))]

                scraper.headers.update({'cookie': f'{auth_csrf_token};  __Secure-next-auth.callback-url=https%3A%2F%2Fwww.mygateway.xyz%2Fdao%2Fgoldfinch; {auth_session_token}'})

                logger.info('Get token and user id')
                data = scraper.get('https://www.mygateway.xyz/api/auth/session').json()
                token = data['token']
                user_id = data['user_id']

                email = create_email()
                scraper.headers.update({'authorization': f'Bearer {token}', 'cookie': '', 'x-hasura-user-id': user_id})

                scraper.post('https://api.mygateway.xyz/v1/graphql',
                             json={
                                 "query": "mutation update_user_profile($id: uuid!, $name: String!, $username: String!, $pic_id: uuid, $email_address: citext!) {\n  update_users_by_pk(\n    pk_columns: {id: $id}\n    _set: {name: $name, username: $username, pic_id: $pic_id, email_address: $email_address, init: true}\n  ) {\n    id\n    name\n    username\n    picture {\n      ...file\n    }\n    email_address\n  }\n}\n\nfragment file on files {\n  id\n  blur\n}",
                                 "variables": {
                                     "name": email.split('@')[0],
                                     "username": email.split('@')[0],
                                     "email_address": email,
                                     "id": user_id
                                 },
                                 "operationName": "update_user_profile"
                             })

                logger.info('Task#1 started')
                answer = [{"questionIdx":0,"answers":[4]},{"questionIdx":1,"answers":[1]},{"questionIdx":2,"answers":[0,2]},{"questionIdx":3,"answers":[1,2]},{"questionIdx":4,"answers":[1]},{"questionIdx":5,"answers":[0,1,2]},{"questionIdx":6,"answers":[3]},{"questionIdx":7,"answers":[1]},{"questionIdx":8,"answers":[1,2]}]
                id = task(scraper, '5fcd95f2-55f4-4b94-96fd-ccf02bcb55fc', 'a3597046-a7ed-4225-8af3-390903edaf51', '46896ba4-eab2-405d-b660-5797cf50278e', answer)

                logger.info('Mint nft')
                mint_nft(scraper, id)

                logger.info('Task#2 started')
                answer = [{"questionIdx":0,"answers":[0]},{"questionIdx":1,"answers":[0]},{"questionIdx":2,"answers":[1]},{"questionIdx":3,"answers":[0]},{"questionIdx":4,"answers":[2]},{"questionIdx":5,"answers":[1]},{"questionIdx":6,"answers":[0]},{"questionIdx":7,"answers":[2]},{"questionIdx":8,"answers":[0]},{"questionIdx":9,"answers":[2]}]
                id = task(scraper, 'f2ab92c7-e488-4fff-82f6-c7495f1e9180', 'b3147e89-ea83-48bb-8c87-86829446605f', '0ff57946-5360-4647-a1a5-f7043858edc4', answer)

                logger.info('Mint nft')
                mint_nft(scraper, id)

                logger.info('Task#3 started')
                answer = [{"questionIdx":0,"answers":[0]},{"questionIdx":1,"answers":[1]},{"questionIdx":2,"answers":[0]},{"questionIdx":3,"answers":[1]},{"questionIdx":4,"answers":[2]},{"questionIdx":5,"answers":[0]}]
                id = task(scraper, '7509bcbc-f674-47dc-be3e-f74b7208eb6d', 'a65e232e-692f-485c-8247-b49a8cefe7b1', '6f8c1f9f-6063-4fe8-a210-0dee7ccb22df', answer)

                logger.info('Mint nft')
                mint_nft(scraper, id)

                logger.info('Task#4 started')
                answer = [{"questionIdx":0,"answers":[0,1,2]},{"questionIdx":1,"answers":[2]},{"questionIdx":2,"answers":[3]},{"questionIdx":3,"answers":[2]},{"questionIdx":4,"answers":[2]},{"questionIdx":5,"answers":[2]}]
                id = task(scraper, 'fe70706f-94eb-4028-b592-a045c4cc33b2', '15a3bda6-856f-4d7c-8c63-17239baaaa14', '42af7da7-dd26-4c42-9eaa-99d466ea7f0f', answer)

                logger.info('Mint nft')
                mint_nft(scraper, id)

                logger.info('Task#5 started')
                answer = [{"questionIdx":0,"answers":[0]},{"questionIdx":1,"answers":[1]},{"questionIdx":2,"answers":[3]},{"questionIdx":3,"answers":[2]},{"questionIdx":4,"answers":[1]},{"questionIdx":5,"answers":[0]}]
                id = task(scraper, 'a233883b-40e0-44e8-95f6-365a7ed81610', 'ea6bd785-cd41-4d5f-a7be-e6ccb7d354fb', '594aa1ae-c2c5-4b06-a579-32268e03d1f4', answer)

                logger.info('Mint nft')
                mint_nft(scraper, id)

        except Exception:
            logger.error("Error\n")

        else:
            with open('successfully.txt', 'a', encoding='utf-8') as file:
                file.write(f'{address}:{private_key}:{email}\n')
            logger.success('Successfully\n')


if __name__ == '__main__':
    print("Bot Goldfinch NFT mint @flamingoat\n")

    user_key = input('Captcha key: ')

    main()