# VirusTotal vHash Maltego Transform

## Introduction
This Maltego Transform accepts a hash and returns hashes of files that share the same 'vHash'.
According to VirusTotal, vHash is "an in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files". There is no further information about vHash at this time and it's not a property that is clearly visible on the web GUI.  

I found it to be very useful pivoting on malicious documents that share an exploit and a similar payload and/or were most likely crafted using the same method.   

Please note that this differs from VirusTotal's similar files ('similar-to:') and yields different results.

## Prerequisites
- VirusTotal Private API key
- Python 2.7.X, requests, json 

## Example
![Alt text](/Screenshot.png?raw=true)

## Setup
With the prerequisites met, clone repository to a local folder.

1. Edit VTvHash.py and insert your VirusTotal private API key.
2. Import VTvHash.mtz to Maltego.
3. Go to Transforms -> Transform Manager -> VTvHash and set:
  - Command line: C:\Python27\python.exe (or your python folder)
  - Working directory: The folder where you cloned this repository to.
  - Uncheck "Show debug info"
