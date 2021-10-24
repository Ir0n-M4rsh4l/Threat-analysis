#/usr/bin/python3

#pour avoir le nombre de fois qu'une techniqe est utilisée par un gpe, voir soit la date, soit par campagne
import requests
from stix2 import MemoryStore
from stix2 import Filter
from stix2.utils import get_type_from_id
import numpy as np
#--------------------------------------------------------------------------------------------------------
#on charge la database src

def get_data_from_branch(domain, branch="master"):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

src = get_data_from_branch("enterprise-attack")
#--------------------------------------------------------------------------------------------------------
#on récupère les techniques utilisées par chaque groupe

def get_techniques_malwares_by_group(thesrc, id_group):

    return thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type','=','uses'),
        Filter('source_ref','=',id_group),
       
    ])

def get_techniques_by_group(id_group):

	tech_group=get_techniques_malwares_by_group(src, id_group)
	tec=[]
	for t in tech_group:
		if get_type_from_id(t.target_ref) == 'attack-pattern':
			tec.append(t.target_ref)
	#print(tec)
	return tec

id_group="intrusion-set--f047ee18-7985-4946-8bfb-4ed754d3a0dd"
get_techniques_by_group(id_group)
#--------------------------------------------------------------------------------------------------------

#On récupère la liste de tous les groupes list_gpe
def list_groups(thesrc):
	 t= thesrc.query([
		Filter('type','=','intrusion-set')
			   ])
	 l=[]
	 for i in t:
	 	l.append(i.id)
	 return l

#print(list_groups(src))

list_gpe=list_groups(src)	
l1=np.array(list_gpe)
np.savetxt("list_gpe.txt",l1,fmt="%s")
#--------------------------------------------------------------------------------------------------------

#on récupère la liste des sous-techniques list_tech, groupés par techniques

def list_techniques(thesrc):
	 t= thesrc.query([
		Filter('type','=','attack-pattern'),
		Filter('x_mitre_is_subtechnique','=',False)
			   ])
	 l=[]
	 for i in t:
	 	l.append(i.id)
	 return l
#attack-pattern--01df3350-ce05-4bdf-bdf8-0a919a66d4a8
#print(list_techniques(src))

list_tech=list_techniques(src)
n=len(list_tech)
print(n)
print("list_tech=")
"""
#print(list_tech)
#l2=np.array(list_tech)
#np.savetxt("list_tech.txt",l2,fmt="%s")
def list_subtechniques(thesrc):
	 t= thesrc.query([
		Filter('type','=','attack-pattern'),
		Filter('x_mitre_is_subtechnique','=',True)
			   ])
	 l=[]
	 for i in t:
	 	l.append(i.id)
	 return l

list_sub=list_subtechniques(src)
m=len(list_sub)
print(m)
l3=np.array(list_sub)
np.savetxt("list_subtech.txt",l3,fmt="%s")
#L[i] est la list des subtechniques de la technique list_tech[i]
def list_subtechniques_by_tech(thesrc):
	L= []
	for i in range(n):
		L.append([])
	#print(L)
	for k in range(n):
		id_t=list_tech[k]
		t=thesrc.query([
			Filter('type','=','relationship'),
			Filter('target_ref','=',id_t)
			])
		for i in t:
			if (i.source_ref in list_sub):
				L[k].append(i.source_ref)
	for k in range(n):
		if L[k]==[]:
			L[k].append(list_tech[k])
	return L
L=list_subtechniques_by_tech(src)

L_final=[]
for i in range(n):
	for j in L[i]:
		L_final.append(j)
taille=len(L_final)
print(taille)
#print(L_final)
#print(list_tech[2])

#--------------------------------------------------------------------------------------------------------

#M tableau : M[i]= list des groups utilisant cette technique ou sous technique
#Pour chaque groupe si il utilise la technique ou sous-technique i, on l'ajoute dans M[i]

M=[]
for i in range(taille):
	M.append([])

for gpe in list_gpe:
	tech=get_techniques_by_group(gpe)
	for t in tech:
		for i in range(taille):
			if t==L_final[i]:
				M[i].append(gpe)

#print(M)
#--------------------------------------------------------------------------------------------------------
"""
#on prend les noms

def name_by_id(id):
	l= src.query(
			Filter('id','=',id)
			)
	for i in l:
		n=i.name
	return n
		
tech_name=[]
for i in list_tech:
	tech_name.append(name_by_id(i))

print(tech_name)
"""
M_name=[]
for i in range(taille):
	M_name.append([])
				
for i in range(taille):
	for j in M[i]:
		M_name[i].append(name_by_id(j))
#print("M_name=")
#print(M_name)
print("------------------------------------------------------------------------------------------")
#--------------------------------------------------------------------------------------------------------
#fonction qui renvoit la technique parent

def get_tech(id_sub):
	t = src.query([
        	Filter('type','=','relationship'),
        	Filter('source_ref','=',id_sub)
        ])

	for i in t:
    		o=i.target_ref
	return o
    	#print(s)
#tec=get_tech("attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597")
#tec=get_tech(list_tech[8])
#print(list_tech[5])
#print(tec)

#List des technniques
techniques=[]
exept=[]
for m in range(taille):
	#print(m)
	if L_final[m] in list_sub:
		t=get_tech(L_final[m])
		techniques.append(t)
	else:
		exept.append(m)
		techniques.append(0)
	
#print(techniques)
#print(len(techniques))
#--------------------------------------------------------------------------------------------------------
#techniques_name

techniques_name=[]		
for i in techniques:
	#print(i)
	if i!=0:
		techniques_name.append(name_by_id(i))

#print("techniques_name=")
#print(techniques_name)
print("--------------------------------------------------------------------------")
#--------------------------------------------------------------------------------------------------------
#on concatène les groupes par technique
tec=[]
k=0
j=1
i=0
M_final=[]
for l in range(n):
	M_final.append([])
#print(len(M_final))
#print(n)
while k<n:	
	#print("k=",k)
	if techniques[i]==0:
		M_final[k]=M_name[i]
		i+=1
		#print(i)
	else:
		M_final[k]=M_name[i]
		i+=1
		#print(i)
		
		while i<taille and techniques[i]==techniques[i-1]:
			M_final[k]=M_final[k]+M_name[i]
			i+=1
	k+=1


#print("M_final=")
#print(M_final)
#print(len(M_final))
#print(len(M_name))
l3=np.array(M_final,dtype=object)
np.savetxt('M_final.txt',l3,fmt='%s')
#--------------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------------
#M_cpt[i][j]=(nom gpe j, nb occurences) pour la tech i
n=len(M_final)

M_cpt=[]
for i in range(n):
	M_cpt.append([])
	m=len(M_final[i])
	L_fini=[]
	for j in range(m):
		gpe=M_final[i][j]
		cpt=0
		if gpe not in L_fini:
			for k in range(j,m):
				if M_final[i][k]==gpe:
					cpt+=1
			M_cpt[i].append((gpe,cpt))
			L_fini.append(gpe)
print("----------------------------------------------------------------------------\n")
print(M_cpt)

#--------------------------------------------------------------------------------------------------------
#M_proba[i][j]=(nom gpej, proba ) pour la tech i

M_proba=[]
for i in range(n):
	M_proba.append([])
	m=len(M_cpt[i])
	total=0
	for j in range(m):
		a,b=M_cpt[i][j]
		total+=b
	for j in range(m):
		a,b=M_cpt[i][j]
		M_proba[i].append((a,b/total))
	
print(len(M_proba))
#--------------------------------------------------------------------------------------------------------

 """




