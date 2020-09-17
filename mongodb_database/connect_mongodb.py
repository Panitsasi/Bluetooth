from pymongo import MongoClient
import core.config as config
import datetime


def connect_to_database(name_of_database):

    c = config.loadConfig()
    connection = c['TESTBED']['CONNECTION_TO_DATABASE']
    client = MongoClient(connection)
    db = client.get_database(name_of_database)
    print('Database found...')
    return [client,db]



def connect_to_collection_info_tests():
    client,db=connect_to_database('Bluetooth_Attack')
    records = db.info_tests
    print('Database connected...')
    return [client,records]



def connect_to_collection_sniffer_data():
    client,db=connect_to_database('Bluetooth_Attack')
    records = db.sniffer_data
    return [client,records]



def insert_data_to_collection_info_tests(name_of_attack):
    c = config.loadConfig()
    info = {

        'Attack': name_of_attack,
        'Day_of_Attack': str(datetime.datetime.today()).split()[0].encode('ascii', 'ignore'),
        'Advertiser_Address': str(c['TESTBED']['ADVERTISER_ADDRESS']),
        'Scanner_Address': str(c['TESTBED']['MASTER_ADDRESS']),
        'Access_Adress': str(int(c['TESTBED']['ACCESS_ADDRESS'], 16)),
        'Port': str(c['TESTBED']['COM_PORT_NRF'])
    }
    client,records=connect_to_collection_info_tests()
    records.insert_one(info)
    return client


def close_connection_to_database(client):
    print('Database closed...')
    client.close()





