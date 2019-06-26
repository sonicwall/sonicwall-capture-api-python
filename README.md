# Capture as Service API(Python)
The capture_api.py is a python module to use the Capture as service API. 

The capture_api_cli.py is a python CLI tool to use the capture_api.py.

## Prerequisites
- You need to get SN/API_KEY to use the API.
- Python 2.7, Python 3.4 and newer. 
- The capture_api.py require **[requests]("https://github.com/kennethreitz/requests)**.
  
   `pip install requests`
- The capture_api_cli.py require **[click](https://github.com/pallets/click/)**.
  
   `pip install click`

## Usage
### capture_api.py
Create an api_client instance with server/sn/api_key.

    from capture_api import CaptureAPI, file_hash
    api_client = CaptureAPI(server, sn, api_key)

Calculate the sha256 of a file, query its report and check the analysis_result before scan it, avoid unnecessary file submission.

    file_path = "D://Authenticode_PE.docx"
    sha256 = file_hash("sha256", file_path)
    # set all_info=True if want to get analysis detail message, see the analysis_summary list.
    status_code, report = api_client.file_report(sha256, all_info=True) 

If the analysis_result is "clean" or "malicious", means the file has been scanned before, we can use the report directly.
if the analysis_result is "pending" or "running", that means the file is under scanning, please wait for the verdict.
If analysis_result is "unknown", which means the file has not been scanned by capture services, we can upload the file to scan it.

    status_code, data = api_client.file_scan(file_path)

We can get a "scan_id" from the "file_scan" response, use it to query the report until the verdict is avaliable.

    scan_id = data["scan_id"]
    timeout = 1000
    wait_seconds = 25
    report = None
    for i in range(int(timeout/wait_seconds)):
        status_code, report = api_client.file_report(scan_id)
        if report["analysis_result"] in ("clean", "malicious"):
            break
        time.sleep(wait_seconds)

We can also get the submission list within a certain time frame(use the after,before parameter), and fetch the records page by page(use the page_size,page_index parameter). 

    status_code, scan_list = api_client.file_list()

To get the network traffic or the screenshots during the dynamic analysis, we need get the artifact list first, then use the specific keywords to download it.

    status_code, artifact = api_client.file_artifact(sha256)
    # these values should got from the artifact response.
    engine, env, type_name = "s", "win7_amd64", "pcap"
    save_folder = "D://download/"
    status_code, attachment_path = api_client.file_download(
        sha256, engine, env, type_name, save_folder)

For details on the JSON response, please consult the **Capture as Services API documentation**. 

### capture_api_cli.py
We need prepare the server/sn/api_key before using the CLI tool.
1. Calculate the sha256 of a file.

        python capture_api_cli.py server sn api_key file-hash sha256 file_path
2. Query the report with sha256, check the analysis_result before scan it.
   
        python capture_api_cli.py server sn api_key file-report sha256
        python capture_api_cli.py server sn api_key file-report sha256 --all_info
3. Upload a file to scan it, get a scan_id in response.
   
        python capture_api_cli.py server sn api_key file-scan file_path

4. Query the report with scan_id.
   
        python capture_api_cli.py server sn api_key file-report scan_id
        python capture_api_cli.py server sn api_key file-report scan_id --all_info
5. Get the scan list within a certain time frame, and fetch the records page by page.
   
        python capture_api_cli.py server sn api_key file-list --after=0 --before=9999999999
         --page_size=10 --page_index=0
6. Get the artifact list during dynamic analysis, we need use the specific keywords in the response to download them.
   
        python capture_api_cli.py server sn api_key file-artifact sha256
7. Download the artifact(pcap/screenshots).
   
        python capture_api_cli.py server sn api_key file-download sha256 engine env type save_dir

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.