# OS Project 3 - Proc Blart: Mallware Cop



##  Real-Time Process Monitor with VirusTotal Check

I use a table, which is self-updating instead of permanently write a new table after the old table in the console.
The table shows the running processes and when one of the defined problems occurs it will change the color for the entry e.g.

Like the project tasks required I included a filter
- for process names,
- memory usage,
- VirusTotal values

If one of this criteria is fullfilled the app perform the given reactions
- kill and move to quarantine
- log a warning
- suspend, dump memory and move to quarantine

The app is near realtime, I have implemented a 5 sec delay for each loop.


## Flowchart
```mermaid
flowchart TD
    A[Start] --> B[Show Table]
    B --> C[Get Processes]
    C --> D[Get Filepath]
    D --> E{System Path?}
    E -->| Yes| F{More Processes?}
    E -->| No| G[Calculate Hash]
    G --> H{Hash in Cache?}
    H -->| Yes| I[Use Cached Result]
    I --> F
    H -->| No| J[API Request to VirusTotal]
    J --> K[Insert Hash in Cache]
    K --> F
    F -->| Yes| C
    F -->| No| B
```

## Reaction Policy
The policy rules are defined in `main.py` in the `apply_policy()` function and can be easily adjusted:

- `SUSPICIOUS_NAMES` - list of process names to kill and quarantine
- Memory threshold: currently set to 500MB
- VirusTotal threshold: currently set to > 3 detections


## Testfiles
To create .exe-testfiles I used pyinstaller.
You can make your own.
First install pyinstaller
```
pip install pyinstaller
```
and now you can run
```
pyinstaller --onefile filename.py
```
it creates a build and a dist folder, the exe will be stored in dist/

### virus.exe
A super simple Python Script which does nothing else then wait.

```
pyinstaller --onefile virus.py
```

### memhog.exe
A super simple Python Script which does nothing else then
- create an empty array
- start a while true
- append for each loop a string of 1.000.000 space-chars to the array ~1MB
- when the array reaches a size of 500 MB it stops to fill it
```
pyinstaller --onefile --hidden-import psutil memhog.py
```

### badhash.exe
Similar to virus.exe but this file process get filtered by name and becomes the hash value from the EICAR testfile.
```
pyinstaller --onefile badhash.py
```