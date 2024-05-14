# SOA-project

## Specifica: Monitor di Riferimento a Livello di Kernel per la Protezione dei File

Questa specifica riguarda un Modulo del Kernel Linux (LKM) che implementa un
monitor di riferimento per la protezione dei file. Il monitor di riferimento può
trovarsi in uno dei seguenti quattro stati:

- OFF: significa che le sue operazioni sono attualmente disabilitate;
- ON: significa che le sue operazioni sono attualmente abilitate;
- REC-ON/REC-OFF: significa che può essere attualmente riconfigurato (sia in
  modalità ON che OFF).

La configurazione del monitor di riferimento si basa su un insieme di percorsi
del file system. Ogni percorso corrisponde a un file/directory che al momento
non può essere aperto in modalità scrittura. Quindi, ogni tentativo di aprire il
percorso in modalità scrittura deve restituire un errore, indipendentemente
dall'ID utente che tenta l'operazione di apertura.

Riconfigurare il monitor di riferimento significa che alcuni percorsi da
proteggere possono essere aggiunti/rimossi. In ogni caso, cambiare lo stato
attuale del monitor di riferimento richiede che il thread che sta eseguendo
questa operazione sia contrassegnato con l'ID utente effettivo impostato su
root, e inoltre la riconfigurazione richiede in input una password specifica del
monitor di riferimento. Ciò significa che la versione crittografata della
password è mantenuta a livello dell'architettura del monitor di riferimento per
eseguire i controlli richiesti.

Spetta al progettista del software determinare se i suddetti stati
ON/OFF/REC-ON/REC-OFF possono essere modificati tramite API VFS o tramite
chiamate di sistema specifiche. Lo stesso vale per i servizi che implementano
ciascun passaggio di riconfigurazione (aggiunta/rimozione di percorsi da
controllare). Insieme alle operazioni a livello del kernel, il progetto dovrebbe
anche consegnare codice/comandi dello spazio utente per invocare l'API di
livello di sistema con parametri corretti.

Oltre alle specifiche sopra indicate, il progetto dovrebbe includere anche la
realizzazione di un file system in cui un singolo file _append-only_ dovrebbe
registrare la seguente tupla di dati (per riga del file) ogni volta che viene
tentato di aprire un percorso del file system protetto in modalità scrittura:

- l'ID del processo TGID
- l'ID del thread
- l'ID utente
- l'ID utente effettivo
- il percorso del programma che sta attualmente tentando l'apertura
- un hash crittografico del contenuto del file del programma

Il calcolo dell'hash crittografico e la scrittura della tupla sopra indicata
dovrebbero essere eseguiti come lavoro differito.

## Singlefile-FS

Aggiunta la funzione per la scrittura in append mode. Il problema che si
riscontrava è che, leggendo la _size_ dalla `struct i_node`, questa era sempre 0
anche se conteneva effettivamente dati. Ho quindi aggiunto una variabile globale
che si aggiorna dopo ogni scrittura coi dati scritti: in questo modo, la
`file_size` corrisponde anche all'offset in cui scrivere i nuovi dati.

Nel file di log, ho trovato questa situazione:

```
TGID: 1786 PID: 1786 UID: 1000 EUID: 1000 prograTGID: 1786 PID: 1786 UID: 1000 EUID: 1000 program path: /usr/bin/zsh file content hash: 4ff9dbd18f4cad5234614cdf6a2b59e0a9a6326b09b8e86f40e1a55b5476d11d
m path: /usr/bin/zsh file content hash: 4ff9dbd18f4cad5234614cdf6a2b59e0a9a6326b09b8e86f40e1a55b5476d11d
```

Il risultato è stato riscontrato con le seguenti istruzioni dalla root del
progetto:

```bash
$ user/add_path ../dir_prova
adding path: ../dir_prova
path added successfully
$ for ((i=0;i<100;i++)); do
echo "asd" > ../dir_prova/asd.txt
done
```

la scrittura sul file di log potrebbe dover essere sincronizzata. È successo
però una sola volta e non riesco a riprodurlo.
