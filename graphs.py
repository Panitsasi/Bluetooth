import matplotlib.pyplot as plt
from mongodb_database.connect_mongodb import *
from sql_database.connect import attacks_date, master_date, advertiser_date

attacks = ['CH_MAP', 'CON_REQ', 'CON_UPD', 'DOS', 'DUMMY', 'FEAT_REQ', 'INV', 'INV_SEQ', 'LEN_REQ', 'LLID',
           'PING_REQ', 'ATT_CRS', 'REJ_IND', 'SIL_LEN', 'ENC_REQ']

# convert unicode to ascii
def convert(input):
    if isinstance(input, dict):
        return dict((convert(key), convert(value)) for key, value in input.iteritems())
    elif isinstance(input, list):
        return [convert(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

############################################### Searching to MongoDB database ###############################################################

#Connect to mongodb_database and count the attacks per day
def Attack_Day(date):

    client,records=connect_to_collection_info_tests()

    reject_indiaction = records.find({"Day_of_Attack":date,'Attack':'Reject Indication'}).count()
    connection_crush  = records.find({"Day_of_Attack":date,'Attack':'Connection Request Crush'}).count()
    channel_map = records.find({"Day_of_Attack":date,'Attack':'Channel Map Request'}).count()
    connection_update = records.find({"Day_of_Attack":date,'Attack':'Connection Update Request'}).count()
    dos = records.find({"Day_of_Attack":date,'Attack':'Dos'}).count()
    dummy = records.find({"Day_of_Attack":date,'Attack':'Dummy'}).count()
    feature_req = records.find({"Day_of_Attack":date,'Attack':'Feature Request'}).count()
    invalid = records.find({"Day_of_Attack":date,'Attack':'Invalid'}).count()
    invalid_sequence = records.find({"Day_of_Attack":date,'Attack':'Invalid Sequence'}).count()
    length_req = records.find({"Day_of_Attack":date,'Attack':'Length Request'}).count()
    llid_deadlock = records.find({"Day_of_Attack":date,'Attack':'LLID Deadlock'}).count()
    ping_req = records.find({"Day_of_Attack":date,'Attack':'Ping Request'}).count()
    att_crush = records.find({"Day_of_Attack":date,'Attack':'Attribute Crush'}).count()
    silent_overflow = records.find({"Day_of_Attack":date,'Attack':'Silent Length Overflow'}).count()
    start_enc_req = records.find({"Day_of_Attack":date,'Attack':'Start Encryption Request'}).count()


    times = [channel_map, connection_crush, connection_update, dos, dummy, feature_req, invalid, invalid_sequence,
             length_req, llid_deadlock, ping_req, att_crush, reject_indiaction, silent_overflow, start_enc_req]

    plt.title(date)
    plt.bar(attacks,times)
    plt.xlabel('Attacks', fontsize=18, color="grey")
    plt.ylabel('Number of Attacks', fontsize=16, color="grey")
    plt.show()
    close_connection_to_database(client)



#Connect to mongodb_database and count the attacks by the master per day
def Attack_Master(date):


    #You can change the master address here
    master = "5d:36:ac:90:0b:23"

    client, records = connect_to_collection_info_tests()

    reject_indiaction = records.find({"Day_of_Attack":date,'Attack':'Reject Indication',"Scanner_Address":master}).count()
    connection_crush  = records.find({"Day_of_Attack":date,'Attack':'Connection Request Crush',"Scanner_Address":master}).count()
    channel_map = records.find({"Day_of_Attack":date,'Attack':'Channel Map Request',"Scanner_Address":master}).count()
    connection_update = records.find({"Day_of_Attack":date,'Attack':'Connection Update Request',"Scanner_Address":master}).count()
    dos = records.find({"Day_of_Attack":date,'Attack':'Dos',"Scanner_Address":master}).count()
    dummy = records.find({"Day_of_Attack":date,'Attack':'Dummy',"Scanner_Address":master}).count()
    feature_req = records.find({"Day_of_Attack":date,'Attack':'Feature Request',"Scanner_Address":master}).count()
    invalid = records.find({"Day_of_Attack":date,'Attack':'Invalid',"Scanner_Address":master}).count()
    invalid_sequence = records.find({"Day_of_Attack":date,'Attack':'Invalid Sequence',"Scanner_Address":master}).count()
    length_req = records.find({"Day_of_Attack":date,'Attack':'Length Request',"Scanner_Address":master}).count()
    llid_deadlock = records.find({"Day_of_Attack":date,'Attack':'LLID Deadlock',"Scanner_Address":master}).count()
    ping_req = records.find({"Day_of_Attack":date,'Attack':'Ping Request',"Scanner_Address":master}).count()
    att_crush = records.find({"Day_of_Attack":date,'Attack':'Attribute Crush',"Scanner_Address":master}).count()
    silent_overflow = records.find({"Day_of_Attack":date,'Attack':'Silent Length Overflow',"Scanner_Address":master}).count()
    start_enc_req = records.find({"Day_of_Attack":date,'Attack':'Start Encryption Request',"Scanner_Address":master}).count()

    times = [channel_map, connection_crush, connection_update, dos, dummy, feature_req, invalid, invalid_sequence,
             length_req, llid_deadlock, ping_req, att_crush, reject_indiaction, silent_overflow, start_enc_req]

    plt.title('Attacker Address:'+master + "        Day of Attack:"+date)
    plt.bar(attacks,times,color=(0.1, 0.1, 0.3, 0.8))
    plt.xlabel('Attacks', fontsize=18,color="grey")
    plt.ylabel('Number of Attacks', fontsize=16,color="grey")
    plt.show()
    close_connection_to_database(client)



#Connect to mongodb_database and count the attacks to a specific advertiser
def Attack_Advertiser(date):


    # You can change the advertiser address here
    advertiser_address = "80:ea:ca:95:66:44"

    client, records = connect_to_collection_info_tests()

    reject_indiaction = records.find({"Day_of_Attack": date, 'Attack': 'Reject Indication',"Advertiser_Address": advertiser_address}).count()
    connection_crush = records.find({"Day_of_Attack": date, 'Attack': 'Connection Request Crush',"Advertiser_Address": advertiser_address}).count()
    channel_map = records.find({"Day_of_Attack": date, 'Attack': 'Channel Map Request',"Advertiser_Address": advertiser_address}).count()
    connection_update = records.find({"Day_of_Attack": date, 'Attack': 'Connection Update Request',"Advertiser_Address": advertiser_address}).count()
    dos = records.find({"Day_of_Attack": date, 'Attack': 'Dos',"Advertiser_Address": advertiser_address}).count()
    dummy = records.find({"Day_of_Attack": date, 'Attack': 'Dummy',"Advertiser_Address": advertiser_address}).count()
    feature_req = records.find({"Day_of_Attack": date, 'Attack': 'Feature Request',"Advertiser_Address": advertiser_address}).count()
    invalid = records.find({"Day_of_Attack": date, 'Attack': 'Invalid',"Advertiser_Address": advertiser_address}).count()
    invalid_sequence = records.find({"Day_of_Attack": date, 'Attack': 'Invalid Sequence',"Advertiser_Address": advertiser_address}).count()
    length_req = records.find({"Day_of_Attack": date, 'Attack': 'Length Request',"Advertiser_Address": advertiser_address}).count()
    llid_deadlock = records.find({"Day_of_Attack": date, 'Attack': 'LLID Deadlock',"Advertiser_Address": advertiser_address}).count()
    ping_req = records.find({"Day_of_Attack": date, 'Attack': 'Ping Request',"Advertiser_Address": advertiser_address}).count()
    att_crush = records.find({"Day_of_Attack": date, 'Attack': 'Attribute Crush',"Advertiser_Address": advertiser_address}).count()
    silent_overflow = records.find({"Day_of_Attack": date, 'Attack': 'Silent Length Overflow',"Advertiser_Address": advertiser_address}).count()
    start_enc_req = records.find({"Day_of_Attack": date, 'Attack': 'Start Encryption Request',"Advertiser_Address": advertiser_address}).count()


    times = [channel_map, connection_crush, connection_update, dos, dummy, feature_req, invalid, invalid_sequence,
             length_req, llid_deadlock, ping_req, att_crush, reject_indiaction, silent_overflow, start_enc_req]


    plt.title('Victim Address:' + advertiser_address + "        Day of Attack:" + date)
    plt.bar(attacks, times, color=(1.0, 0.8, 0.7, 0.9))
    plt.xlabel('Attacks', fontsize=18, color="grey")
    plt.ylabel('Number of Attacks', fontsize=16, color="grey")
    plt.show()
    close_connection_to_database(client)








def attack_day_SQL(date):


    reject_indiaction =attacks_date('Reject Indication',date)
    connection_crush = attacks_date('Connection Request Crush',date)
    channel_map = attacks_date('Channel Map Request',date)
    connection_update = attacks_date('Connection Update Request',date)
    dos = attacks_date('Dos',date)
    dummy = attacks_date('Dummy',date)
    feature_req = attacks_date('Feature Request',date)
    invalid = attacks_date('Invalid',date)
    invalid_sequence = attacks_date('Invalid Sequence',date)
    length_req = attacks_date('Length Request',date)
    llid_deadlock = attacks_date('LLID Deadlock',date)
    ping_req = attacks_date('Ping Request',date)
    att_crush = attacks_date('Attribute Crush',date)
    silent_overflow = attacks_date('Silent Length Overflow',date)
    start_enc_req = attacks_date('Start Encryption Request',date)

    times = [channel_map, connection_crush, connection_update, dos, dummy, feature_req, invalid, invalid_sequence,
             length_req, llid_deadlock, ping_req, att_crush, reject_indiaction, silent_overflow, start_enc_req]

    plt.title(date)
    plt.bar(attacks, times)
    plt.xlabel('Attacks', fontsize=18, color="grey")
    plt.ylabel('Number of Attacks', fontsize=16, color="grey")
    plt.show()






def master_day_SQL(date):

    master="5d:36:ac:90:0b:23"
    reject_indiaction =master_date('Reject Indication',date)
    connection_crush = master_date('Connection Request Crush',date)
    channel_map = master_date('Channel Map Request',date)
    connection_update = master_date('Connection Update Request',date)
    dos = master_date('Dos',date)
    dummy = master_date('Dummy',date)
    feature_req = master_date('Feature Request',date)
    invalid = master_date('Invalid',date)
    invalid_sequence = master_date('Invalid Sequence',date)
    length_req = master_date('Length Request',date)
    llid_deadlock = master_date('LLID Deadlock',date)
    ping_req = master_date('Ping Request',date)
    att_crush = master_date('Attribute Crush',date)
    silent_overflow = master_date('Silent Length Overflow',date)
    start_enc_req = master_date('Start Encryption Request',date)

    times = [channel_map, connection_crush, connection_update, dos, dummy, feature_req, invalid, invalid_sequence,
             length_req, llid_deadlock, ping_req, att_crush, reject_indiaction, silent_overflow, start_enc_req]

    plt.title('Attacker Address:' + master + "        Day of Attack:" + date)
    plt.bar(attacks, times, color=(0.1, 0.1, 0.3, 0.8))
    plt.xlabel('Attacks', fontsize=18, color="grey")
    plt.ylabel('Number of Attacks', fontsize=16, color="grey")
    plt.show()







def advertiser_day_SQL(date):

    advertiser = '80:ea:ca:95:66:44'
    reject_indiaction =advertiser_date('Reject Indication',date)
    connection_crush = advertiser_date('Connection Request Crush',date)
    channel_map = advertiser_date('Channel Map Request',date)
    connection_update = advertiser_date('Connection Update Request',date)
    dos = advertiser_date('Dos',date)
    dummy = advertiser_date('Dummy',date)
    feature_req = advertiser_date('Feature Request',date)
    invalid = advertiser_date('Invalid',date)
    invalid_sequence = advertiser_date('Invalid Sequence',date)
    length_req = advertiser_date('Length Request',date)
    llid_deadlock = advertiser_date('LLID Deadlock',date)
    ping_req = advertiser_date('Ping Request',date)
    att_crush = advertiser_date('Attribute Crush',date)
    silent_overflow = advertiser_date('Silent Length Overflow',date)
    start_enc_req = advertiser_date('Start Encryption Request',date)

    times = [channel_map, connection_crush, connection_update, dos, dummy, feature_req, invalid, invalid_sequence,
             length_req, llid_deadlock, ping_req, att_crush, reject_indiaction, silent_overflow, start_enc_req]


    plt.title('Victim Address:' + advertiser + "        Day of Attack:" + date)
    plt.bar(attacks, times, color=(1.0, 0.8, 0.7, 0.9))
    plt.xlabel('Attacks', fontsize=18, color="grey")
    plt.ylabel('Number of Attacks', fontsize=16, color="grey")
    plt.show()




#Menu function
def menu():

        type_database='SQL'

        print ('Starting Day: 2020/09/07')
        print(
        '--------------------------------------------------------------------------------------------------------------')
        print('Graphs')
        print(
        '--------------------------------------------------------------------------------------------------------------')

        print ("Press 1 for graph Attack-Date")
        print ("Press 2 for graph Attack-Master Address")
        print ("Press 3 for graph Attack-Advertiser Address")
        print(
        '--------------------------------------------------------------------------------------------------------------')
        try :ch = int(input("Choice:"))
        except:print("Wrong Input.Please try again .")
        print(
        '--------------------------------------------------------------------------------------------------------------')

        if ch == 1 and type_database=='MONGODB':

            date = str(input('Give date:(YYYYMMDD):'))
            date = date[0:4] + "-" + date[4:6] + "-" + date[6:]
            print ('Successful Input')
            Attack_Day(date)

        elif ch == 1 and type_database == 'SQL':

            date = str(input('Give date:(YYYYMMDD):'))
            date = date[0:4] + "-" + date[4:6] + "-" + date[6:]
            print ('Successful Input')
            attack_day_SQL(date)



        # master address = 5d:36:ac:90:0b:23
        elif ch == 2  and type_database=='MONGODB':
            # master = input('Give me the master address:')
            date = str(input('Give date:(YYYYMMDD):'))
            date = date[0:4] + "-" + date[4:6] + "-" + date[6:]
            print ('Successful Input')
            Attack_Master(date)

        elif ch == 2  and type_database=='SQL':
            # master = input('Give me the master address:')
            date = str(input('Give date:(YYYYMMDD):'))
            date = date[0:4] + "-" + date[4:6] + "-" + date[6:]
            print ('Successful Input')
            master_day_SQL(date)



        elif ch == 3  and type_database=='MONGODB':
            # advertiser_address = input('Give me the advertiser address:')
            date = str(input('Give date:(YYYYMMDD):'))
            date = date[0:4] + "-" + date[4:6] + "-" + date[6:]
            print ('Successful Input')
            Attack_Advertiser(date)


        elif ch == 3 and type_database == 'SQL':
            # advertiser_address = input('Give me the advertiser address:')
            date = str(input('Give date:(YYYYMMDD):'))
            date = date[0:4] + "-" + date[4:6] + "-" + date[6:]
            print ('Successful Input')
            advertiser_day_SQL(date)



        else:
            print ('Wrong Input')




if __name__ == "__main__":
    menu()