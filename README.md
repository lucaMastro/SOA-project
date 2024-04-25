# SOA-project

## Singlefile-FS

Aggiunta la funzione per la scrittura in append mode. Il problema che si
riscontrava è che, leggendo la _size_ dalla `struct i_node`, questa era sempre 0
anche se conteneva effettivamente dati. Ho quindi aggiunto una variabile globale
che si aggiorna dopo ogni scrittura coi dati scritti: in questo modo, la
`file_size` corrisponde anche all'offset in cui scrivere i nuovi dati.

