import csv

f = open('adv_exports1.csv')
csv_f = csv.reader(f)
channel=[]
type=[]
adv_triplets=[]
adv_triplet=[]
delta=[]
stri=[]


for row in csv_f:
    channel.append(row[2])
    type.append(row[3])
    stri.append(row[10])
for i in stri :
    delta.append(i)

for i in range (1,len(delta),1):
    print delta[i]
    print delta[i][3:18]


for i in range (1,len(delta),1):

    if type[i] != "ADV_IND" :
        continue
    else:
        print delta[i]
    try:
        delta[i] = float(delta[i][12:-1]) * 1.0 /1000# converted to millisecond
        print delta[i]
    except:
        pass
    #print delta[i]
    #print "\n"
    if (delta[i]) < 1:
        adv_triplet.append(channel[i])
    else:
        if adv_triplet != []:
            adv_triplets.append(adv_triplet)
            adv_triplet = []
print adv_triplets