import pandas as pd 
import xml.etree.ElementTree as ET

dataFile = 'data/nmap_VulScan_A.xml'

tree = ET.parse(dataFile)
root = tree.getroot()
root.tag

df_host_cols = ["state", "reason", "reason_ttl", "addr", "addrtype",
           "macaddr", "macaddrtype", "vendor", "pCount", "sCount"]
rows_host = []

df_port_cols = ["parent_host", "protocol", "portid", "state", "reason",
             "reason_ttl", "name", "method", "conf", "port_uid"]
rows_port = []

df_script_cols = ["parent_port",
                  "script_id",
                  "script_output"]
rows_script = []

# Iterate over Hosts
if root.find('host'):
    for host in root.iter('host'):

        # Extract Host info
        state = host.find('status').attrib['state']
        reason = host.find('status').attrib['reason']
        reason_ttl = host.find('status').attrib['reason_ttl']

        # First address
        addr = host.find('address').attrib['addr']
        addrtype = host.find('address').attrib['addrtype']

        if len(host.findall('address'))>1:
            # Mac address
            macaddr = host.findall('address')[1].attrib['addr']
            macaddrtype = host.findall('address')[1].attrib['addrtype']
            vendor = host.findall('address')[1].attrib['vendor']

            #print(macaddrtype, macaddr, vendor)
        else:
            macaddr = ''
            macaddrtype = ''
            vendor = ''
        
        print(addr, state, macaddrtype, macaddr, vendor)
        
        # Iterate over ports and count them for host value
        pCount = 0
        sCount = 0
        for port in host.iter('port'):
            pCount = pCount + 1
            parent_host = addr
            protocol = port.attrib['protocol']
            portid = port.attrib['portid']
            state = port.find('state').attrib['state']
            reason =  port.find('state').attrib['reason']
            reason_ttl =  port.find('state').attrib['reason_ttl']
            name =  port.find('service').attrib['name']
            method = port.find('service').attrib['method']
            conf = port.find('service').attrib['conf']
            port_uid = str(addr + portid)
            
            # Account for optional port values
            try:
                product = port.find('service').attrib['product']
            except:
                procuct = ''
            try:
                version = port.find('service').attrib['version']
            except:
                version = ''   
            print('    ' + portid, protocol, state, name, product, version)
            
            # Account for optional script values
            try:
                for script in port.iter('script'):
                    sCount = sCount + 1
                    parent_port = port_uid
                    script_id = script.attrib['id']
                    try:
                        script_output = script.attrib['output']
                    except:
                        script_output = 'ERROR'
                    print('        '+ script_id,)
                    
                    rows_script.append({"parent_port": parent_port,
                                        "script_id": script_id,
                                        "script_output": script_output})
            except:
                pass
            
            
            rows_port.append({"parent_host": parent_host,
                              "protocol": protocol,
                              "portid": portid,
                              "state": state,
                              "reason": reason,
                              "reason_ttl": reason_ttl,
                              "name": name,
                              "method": method,
                              "conf": conf,
                              "port_uid": port_uid})
            
        rows_host.append({"state": state,
                          "reason": reason,
                          "reason_ttl": reason_ttl,
                          "addr": addr,
                          "addrtype": addrtype,
                          "macaddr": macaddr,
                          "macaddrtype": macaddrtype,
                          "vendor": vendor,
                          "pCount": pCount,
                          "sCount": sCount})
        

df_h = pd.DataFrame(rows_host, columns = df_host_cols)
df_p = pd.DataFrame(rows_port, columns = df_port_cols)
df_s = pd.DataFrame(rows_script, columns = df_script_cols)

#df_h
#df_p
#df_s
