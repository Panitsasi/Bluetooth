import sqlite3
import csv
from sqlite3 import Error
import os



###################################### Operations on  database Info_tests ############################################################


def insert_data_to_link_layer_tests(advertiser,master,access_addr,day_attack,attack,port):


    try:
        conn = sqlite3.connect('sqldatabase.db')
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO Info_tests VALUES(?,?,?,?,?,?);""",(advertiser,day_attack,access_addr,master,attack,port))
        conn.commit()
        conn.close()
    except:
        print('An exception found while opening/inserting data to SQL_database')



def delete_info_tests():
    try:
        conn = sqlite3.connect('sqldatabase.db')
        cursor = conn.cursor()
        print("Opened mongodb_database successfully")
        cursor.execute('DELETE FROM Info_tests WHERE TRUE')
        conn.commit()
        print('Data deleted succesfully')
        conn.close()
        print('Database closed')
    except :
        print('An exception found while opening/deleting data to SQL_database')




def attacks_date(attack,date):

        try:
            conn = sqlite3.connect(os.path.join(os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)),'sqldatabase.db'))
            cursor = conn.cursor()
            cursor.execute(
                'SELECT COUNT(*) AS Number_of_Attacks FROM Info_tests  WHERE Day_of_Attack="{}" AND Attack="{}"  ;'.format(date,attack))

            data = cursor.fetchall()
            return data[0][0]
        except:
            print('An exception found while opening/inserting data to SQL_database')

def master_date(attack,date):

        try:
                master='5d:36:ac:90:0b:23' # You can change here the master address
                conn = sqlite3.connect(
                    os.path.join(os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)),
                                 'sqldatabase.db'))
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT COUNT(*) AS Number_of_Attacks FROM Info_tests  WHERE Day_of_Attack="{}" AND Master_Address="{}" AND Attack="{}"  ;'.format(
                        date, master,attack))

                data = cursor.fetchall()
                return data[0][0]

        except:
                print('An exception found while opening/inserting data to SQL_database')

def advertiser_date(attack, date):

            try:
                advertiser = '80:ea:ca:95:66:44'  # You can change here the advertiser address
                conn = sqlite3.connect(
                    os.path.join(os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)),
                                 'sqldatabase.db'))
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT COUNT(*) AS Number_of_Attacks FROM Info_tests  WHERE Day_of_Attack="{}" AND Advertiser_Address="{}" AND Attack="{}"  ;'.format(
                        date, advertiser, attack))

                data = cursor.fetchall()
                return data[0][0]

            except:
                print('An exception found while opening/inserting data to SQL_database')


###################################### Operations on  database Sniffer_data ############################################################


def insert_sniffer_data_to_sql(data):

    '''data form: dictionairy'''

    try:
        conn = sqlite3.connect('sqldatabase.db')
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO Sniffer_data VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (data['Bookmark'], data['Frame_diesh'], data['Channel'], data['Type'], data['AddrTypeI'],
                        data['InitA_ScanA'], data['AddrTypeA'], data['AdvA'], data['Len'], data['Frame'], data['Size'],
                        data['Delta'], data['Timestamp']))
        conn.commit()
        conn.close()


    except:
        print('An exception found while opening/inserting data to SQL_database')


def delete_sniffer_data():
    try:
        conn = sqlite3.connect('sqldatabase.db')
        cursor = conn.cursor()
        print("Opened mongodb_database successfully")
        cursor.execute('DELETE FROM Sniffer_data WHERE TRUE')
        conn.commit()
        print('Data deleted succesfully')
        conn.close()
        print('Database closed')
    except :
        print('An exception found while deleting data from SQL_database')




#########################################################################################################################################



#print( os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)))
#print os.path.join(os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)),'sqldatabase.db')

print(attacks_date('Dos','2020-09-17'))
print(master_date('Dos','2020-09-17'))