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
#on récupère les malwares utilisés par chaque groupe

def get_techniques_malwares_by_group(thesrc, id_group):

    return thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type','=','uses'),
        Filter('source_ref','=',id_group),
       
    ])

def get_malwares_by_group(id_group):

	tech_group=get_techniques_malwares_by_group(src, id_group)
	tec=[]
	for t in tech_group:
		if get_type_from_id(t.target_ref) == 'tool':
			tec.append(t.target_ref)
	#print(tec)
	return tec

id_group="intrusion-set--f047ee18-7985-4946-8bfb-4ed754d3a0dd"
print(get_malwares_by_group(id_group))

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
#l1=np.array(list_gpe)
#np.savetxt("list_gpe.txt",l1,fmt="%s")
#--------------------------------------------------------------------------------------------------------

#on récupère la liste des malwares

def list_malwares(thesrc):
	 t = thesrc.query([
		Filter('type','=','tool'),
			   ])
	 l=[]
	 for i in t:
	 	l.append(i.id)
	 return l
#attack-pattern--01df3350-ce05-4bdf-bdf8-0a919a66d4a8
#print(list_techniques(src))

list_mal=list_malwares(src)
print(list_mal)
n=len(list_mal)
print(n)
#l2=np.array(list_tech)
#np.savetxt("list_tech.txt",l2,fmt="%s")

#--------------------------------------------------------------------------------------------------------

#M tableau : M[i]= list des groups utilisant le malware i
#Pour chaque groupe si il utilise le malware i, on l'ajoute dans M[i]

M=[]
for i in range(n):
	M.append([])

for gpe in list_gpe:
	tech=get_malwares_by_group(gpe)
	for t in tech:
		for i in range(n):
			if t==list_mal[i]:
				M[i].append(gpe)

print(M)
#--------------------------------------------------------------------------------------------------------

#on prend les noms

def name_by_id(id):
	l= src.query(
			Filter('id','=',id)
			)
	for i in l:
		n=i.name
	return n
		


M_name=[]
for i in range(n):
	M_name.append([])
				
for i in range(n):
	for j in M[i]:
		M_name[i].append(name_by_id(j))
#print("M_name=")
print(M_name)
print("------------------------------------------------------------------------------------------")

name_tools=[]
for i in range(len(list_mal)):
	name_tools.append(name_by_id(list_mal[i]))
print(name_tools)

#--------------------------------------------------------------------------------------------------------
#M_cpt[i][j]=(nom gpe j, nb occurences) pour la tech i
#n=len(M_final)

M_cpt=[]
for i in range(n):
	M_cpt.append([])
	m=len(M[i])
	L_fini=[]
	for j in range(m):
		gpe=M_name[i][j]
		cpt=0
		if gpe not in L_fini:
			for k in range(j,m):
				if M_name[i][k]==gpe:
					cpt+=1
			M_cpt[i].append((gpe,cpt))
			L_fini.append(gpe)
print("----------------------------------------------------------------------------\n")
#print(M_cpt)
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
	
print(M_proba)

