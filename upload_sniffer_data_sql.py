import  csv
import sqlite3
from sql_database.connect import insert_sniffer_data_to_sql, delete_sniffer_data


def upload_data():

    row=[]
    #Put the name of your csv_file here
    with open('adv_exports1.csv','r') as csv_file :
        csv_reader=csv.reader(csv_file)
        next(csv_reader)

        for line in csv_reader :
            row=line
            #data of csv file

            data={

                'Bookmark' : str(row[0]),
                'Frame_diesh' : str(row[1]),
                'Channel' : str(row[2]),
                'Type' : str(row[3]),
                'AddrTypeI' : str(row[4]),
                'InitA_ScanA' : str(row[5]),
                'AddrTypeA' : str(row[6]),
                'AdvA' : str(row[7]),
                'Len' :str(row[8]),
                'Frame' : str(row[9]),
                'Size' :str(row[10]),
                'Delta' : str(row[11]),
                'Timestamp' :str(row[12])

            }

            # Insert data to mongodb_database
            insert_sniffer_data_to_sql(data)


    csv_file.close()
    print('Csv file closed.')




if __name__ == "__main__" :


    print('Press 1 to insert sniffer-data to the SQL_database.')
    print('Press 2 to delete sniffer-data to the SQL_database.')
    user= int(input('Choose:'))
    print('-----------------------------------------------------------------------------------------------------')
    if user==1 :
        upload_data()

    elif user==2:
        delete_sniffer_data()