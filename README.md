Duomenų bazė veikia pačiame kode sqlite3, todėl nereikia naudoti atskiros.
Keliams naudojama flask biblioteka.
Kodo paleidimui pirmą kartą reikia suteikti paleidimo  teises: sudo chmod +x ./run.sh
Kodo paleidimas ./run.sh
Svetainė prieinama http://127.0.0.1:5000/



OpenAPI specifikacija 
http://127.0.0.1:5000/docs

404 Kai resursas negali būti rastas
http://127.0.0.1:5000/users/neegzistuoja123

422 Kai blogas per page
http://127.0.0.1:5000/users?per_page=0

400 Kai bad json POST
http://127.0.0.1:5000/users
{
  "username":

201 Kai sukuriamas POST
http://127.0.0.1:5000/users
{
  "username": "bandymas",
  "role": "user",
  "name": "Jonas",
  "surname": "Jonaitis",
  "mail": "bandymas@example.com",
  "password": "test12345"
}

228 neleidžiamas laukas pakeistas username PUT
http://127.0.0.1:5000/users/bandymas
{
  "username": "bandymas",
  "role": "admin",
  "name": "Petras",
  "surname": "Petraitis",
  "mail": "bandymas@example.com",
  "password": "test12345"
}

200 OK pakeista info esamo PUT
http://127.0.0.1:5000/users/bandymas
{
  "role": "admin",
  "name": "Petras",
  "surname": "Petraitis",
  "mail": "bandymas@example.com",
  "password": "test12345"
}

204 Kai trinama, nereikia body DELETE
http://127.0.0.1:5000/users/bandymas


POSTMAN Collections/tests 15api metodų

dashboard
http://127.0.0.1:5000/dashboard

puslapiavimas
http://127.0.0.1:5000/users?page=1&per_page=2

Filtravimas
http://127.0.0.1:5000/users?role=admin
