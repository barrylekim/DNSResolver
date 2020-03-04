package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.util.*;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public class DNSLookupService {

    private static int[] generatedQueryIDs = new int[65536];
    private static int totalQueryCount = 0;

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();
    private static Set<Integer> queryIDArray = new HashSet<>();
    private static Stack<InetAddress> inetAddressStack = new Stack<InetAddress>();
    private static Random random = new Random();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println(
                    "where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null)
                break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty())
                continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") || commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") || commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard
     * output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, -1));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to
     *                         CNAME redirection. The initial call should be made
     *                         with 0 (zero), while recursive calls for regarding
     *                         CNAME results should increment this value by 1. Once
     *                         this value reaches MAX_INDIRECTION_LEVEL, the
     *                         function prints an error message and returns an empty
     *                         set.
     * @return A set of resource records corresponding to the specific query
     *         requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
        if (indirectionLevel == -1){
            inetAddressStack.push(rootServer);
            indirectionLevel = 0;
        }
        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        System.out.println("Indirection level :" + indirectionLevel);

        // System.out.println("Top of stack is: "+inetAddressStack.peek());
        Set<ResourceRecord> cachedResult = cache.getCachedResults(node);
        if (cachedResult.isEmpty()) {
            
            // Check Cache for CNAME
            DNSNode cNameNode = new DNSNode(node.getHostName(), RecordType.getByCode(5));
            Set<ResourceRecord> cNameCachedResult = cache.getCachedResults(cNameNode);

            if (!cNameCachedResult.isEmpty()){
                retrieveResultsFromServer(cNameNode, rootServer);
                getResults(node, indirectionLevel + 1);
            }

            if (!inetAddressStack.isEmpty()) {
            retrieveResultsFromServer(node, inetAddressStack.pop());
            getResults(node, indirectionLevel);
            }
        }

        return cache.getCachedResults(node);
    }

    // private static void getResultsHelper(DNSNode node, int indirectionLevel){

    // retrieveResultsFromServer(node, stack.push());
    // getResults(node, indirectionLevel++);
    // }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in
     * iterative mode, and the query is repeated with a new server if the provided
     * one is non-authoritative. Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        // TODO To be completed by the student

        byte[] queryBuffer = createQuery(node);

        DatagramPacket queryPacket = new DatagramPacket(queryBuffer, queryBuffer.length, server, DEFAULT_DNS_PORT);
        try {
            socket.send(queryPacket);
        } catch (IOException e) {
            System.out.println(e);
        }

        // TODO receive the query and then decode it
        byte[] responseBuffer = new byte[1024];
        DatagramPacket responsePacket = new DatagramPacket(responseBuffer, responseBuffer.length);
        try {
            socket.receive(responsePacket);
            try {
                ArrayList<ResourceRecord> additionalRecords = decodeResponse(responseBuffer, node);
                for (ResourceRecord a : additionalRecords) {
                    if (a.getNode().getType() == node.getType()) {
                        inetAddressStack.push(a.getInetResult());
                        break;
                    }
                }
            } catch (Exception e){
                System.out.println(e);
                return;
            }
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    private static int getIntFromByteArray(byte[] b) {
        if (b.length == 2) {
            return ((b[0] & 0xFF) << 8) + (b[1] & 0xFF);
        } else {
            return ((b[0] & 0xFF) << 24) + ((b[1] & 0xFF) << 16) + ((b[2] & 0xFF) << 8) + (b[3] & 0xFF);
        }
    }

    private static ArrayList<ResourceRecord> decodeResponse(byte[] responseBuffer, DNSNode node) throws Exception {
        ArrayList<ResourceRecord> results = new ArrayList<ResourceRecord>();

        int responseID = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, 0, 2));
        int QR = (responseBuffer[2] & 0x80) >>> 7;
        int opCode = (responseBuffer[2] & 0x78) >>> 3;
        int AA = (responseBuffer[2] & 0x04) >>> 2;
        int TC = (responseBuffer[2] & 0x02) >>> 1;
        int RD = responseBuffer[2] & 0x01;

        int RA = responseBuffer[3] & 0x80;
        int RCODE = responseBuffer[3] & 0x0F;

        int QDCOUNT = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, 4, 6));
        int ANCOUNT = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, 6, 8));
        int NSCOUNT = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, 8, 10));
        int ARCOUNT = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, 10, 12));

        String hostName = "";
        int ptr = 12;

        switch (RCODE) {
            case 1:
                throw new Exception("Format error - The name server was unable to interpret the query");
            case 2:
                throw new Exception("Server failure - The name server was unable to process this query due to a problem with the name server");
            
            case 3:
                throw new Exception("Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist");
                
            case 4:
                throw new Exception("Not Implemented -The name server does not support the requested kind of query");
                
            case 5:
                throw new Exception("Refused - The name server refuses to perform the specified operation for policy reasons");
            case 0:
                while (responseBuffer[ptr] != 0) {
                    int partlength = responseBuffer[ptr];
                    int ptr2 = ptr + 1;
                    for (int i = 0; i < partlength; i++) {
                        char letter = (char) responseBuffer[ptr2];
                        hostName = hostName + letter;
                        ptr2++;
                    }
                    hostName = hostName + ".";
                    ptr = ptr + partlength + 1;
                }

                hostName = hostName.substring(0, hostName.length() - 1); // Get rid of the redundant "." at the end


                ptr++;
                int QTYPE = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, ptr, ptr += 2));
                int QCLASS = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, ptr, ptr += 2));

                // Need to decode Answer if there is one
                if (AA == 1) {
                    results = new ArrayList<ResourceRecord>();
                    for (int i = 0; i < ANCOUNT; i++) {
                        HashMap<String, Object> temp = decodeRecord(responseBuffer, ptr);
                        ResourceRecord record = (ResourceRecord) temp.get("record");
                        ptr = (int) temp.get("ptr");
                        results.add(record);
                        cache.addResult(record);
                        // if(record.getType() == RecordType.getByCode(5)){
                        //     DNSNode cNameNode = new DNSNode(record.getHostName(), node.getType());
                        //     Set<ResourceRecord> cnameset = getResults(cNameNode, 0);
                        //     results.addAll(cnameset);
                        // }
                    }
                    System.out.println("Entered AA==1");
                    
                    return results;
                }

                // Pointer now pointing at first nameserver
                ArrayList<ResourceRecord> listOfNameServers = new ArrayList<ResourceRecord>();
                // Name server
                for (int i = 0; i < NSCOUNT; i++) {
                    HashMap<String, Object> temp = decodeRecord(responseBuffer, ptr);
                    ResourceRecord record = (ResourceRecord) temp.get("record");
                    ptr = (int) temp.get("ptr");
                    listOfNameServers.add(record);
                }

                ArrayList<ResourceRecord> listOfAdditionalRecords = new ArrayList<ResourceRecord>();
                // Additional records
                for (int i = 0; i < ARCOUNT; i++) {
                    HashMap<String, Object> temp = decodeRecord(responseBuffer, ptr);
                    ResourceRecord record = (ResourceRecord) temp.get("record");
                    ptr = (int) temp.get("ptr");
                    listOfAdditionalRecords.add(record);
                    cache.addResult(record);
                }


                ArrayList<ResourceRecord> resourceRecords = new ArrayList<ResourceRecord>();

                // Match the sames servers with additional records
                for (ResourceRecord r : listOfNameServers) {
                    String nameServer = r.getTextResult().trim();
                    for (ResourceRecord a : listOfAdditionalRecords) {
                        if (nameServer.equals(a.getHostName().trim())) {
                            resourceRecords.add(a);
                        }
                    }
                }

                if (resourceRecords.isEmpty() && !listOfNameServers.isEmpty()){
                    ResourceRecord firstRecord = listOfNameServers.get(0);
                    DNSNode sideNode = new DNSNode(firstRecord.getHostName(), RecordType.getByCode(1));
                    Set<ResourceRecord> sideNodeResourceRecords = getResults(sideNode, -1);
                    for(ResourceRecord r: sideNodeResourceRecords) {
                        resourceRecords.add(r);
                    }
                }

                    return resourceRecords;
                }

                return new ArrayList<ResourceRecord>();
    }

    private static HashMap<String, Object> decodeRecord(byte[] responseBuffer, int ptr) {
        HashMap<String, Object> result = new HashMap<String, Object>();
        ResourceRecord singleRecord = null;
        HashMap<String, Object> temp = getName(responseBuffer, ptr);
        String hostName = (String) temp.get("name");
        hostName = hostName.substring(0, hostName.length() - 1); // Get rid of the redundant "." at the end

        ptr = (int) temp.get("ptr");
        int typeCode = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, ptr, ptr += 2));
        int classCode = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, ptr, ptr += 2));
        long TTL = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, ptr, ptr += 4));
        int RDATALength = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, ptr, ptr += 2));

        if (typeCode == 1) { // Type A, Host address, ipv4
            String ipv4 = "";
            for (int i = 0; i < RDATALength; i++) {
                int bite = responseBuffer[ptr] & 0xFF;
                ipv4 = ipv4 + bite + ".";
                ptr++;
            }
            ipv4 = ipv4.substring(0, ipv4.length() - 1); // Get rid of the redundant "." at the end
            try {
                InetAddress recordip = null;
                recordip = InetAddress.getByName(ipv4);
                singleRecord = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, recordip);
            } catch (UnknownHostException e) {
                System.out.println("Error occured while InetAddress.getByName(ipv4)");
            }
        } else if (typeCode == 28) { // Type AAAA, Host address, ipv6
            String ipv6 = "";
            for (int i = 0; i < RDATALength / 2; i++) {
                int bite = getIntFromByteArray(Arrays.copyOfRange(responseBuffer, ptr, ptr += 2));
                String hex = Integer.toHexString(bite);
                ipv6 = ipv6 + hex + ":";
            }
            ipv6 = ipv6.substring(0, ipv6.length() - 1); // Get rid of the redundant "." at the end
            try {
                InetAddress recordip = null;
                recordip = InetAddress.getByName(ipv6);
                singleRecord = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, recordip);
            } catch (UnknownHostException e) {
                System.out.println("Error occured while InetAddress.getByName(ipv4)");
            }
        } else { // Authoritative nameservers and everything else
            HashMap<String, Object> nameAndPointer = getName(responseBuffer, ptr);
            String data = (String) nameAndPointer.get("name");
            data = data.substring(0, data.length() - 1); // Get rid of the redundant "." at the end
            ptr = (int) nameAndPointer.get("ptr");
            singleRecord = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, data);
        }

        result.put("record", singleRecord);
        result.put("ptr", ptr);
        return result;
    }

    private static HashMap<String, Object> getName(byte[] responseBuffer, int ptr) {
        HashMap<String, Object> result = new HashMap<String, Object>();
        String name = "";
        int partlength = responseBuffer[ptr] & 0xFF;
        int compressioncode = responseBuffer[ptr] & 0xFF;
        int tempptr = ptr;
        // Get the new pointer pointing to the correct offset stated by the compression
        // bits
        while (partlength >= 192) {
            int newptr = ((partlength - 192) << 8) + responseBuffer[ptr + 1] & 0xFF;
            partlength = responseBuffer[newptr];
            tempptr = newptr;
        }

        while (responseBuffer[tempptr] != 0) {
            int labellength = responseBuffer[tempptr] & 0xFF;
            if (labellength >= 192) {
                int newptr = 0;
                while (labellength >= 192) {
                    newptr = ((labellength - 192) << 8) + responseBuffer[tempptr + 1] & 0xFF;
                    labellength = responseBuffer[newptr];
                }
                name = name + getNameHelper(responseBuffer, newptr);
                // packet compression is 2 bytes but tempptr is incremented once more below so
                // we only add one
                tempptr = tempptr + 1;
                break;
            }

            int ptr2 = tempptr + 1;
            for (int i = 0; i < labellength; i++) {
                char letter = (char) responseBuffer[ptr2];
                name = name + letter;
                ptr2++;
            }
            name = name + ".";
            tempptr = tempptr + labellength + 1;
        }

        tempptr++; // Move tempptr pass 00 that marks the end of the address
        if (compressioncode >= 192) {
            ptr = ptr + 2;
        } else {
            ptr = tempptr;
        }
        result.put("name", name);
        result.put("ptr", ptr);
        return result;
    }

    private static String getNameHelper(byte[] responseBuffer, int ptr) {
        String hostName = "";
        while (responseBuffer[ptr] != 0) {
            int partlength = responseBuffer[ptr] & 0xFF;
            if (partlength >= 192) {
                int newptr = ((partlength - 192) << 8) + responseBuffer[ptr + 1] & 0xFF;
                hostName = hostName + getNameHelper(responseBuffer, newptr);
                break;
            }
            int ptr2 = ptr + 1;
            for (int i = 0; i < partlength; i++) {
                char letter = (char) responseBuffer[ptr2];
                hostName = hostName + letter;
                ptr2++;
            }
            hostName = hostName + ".";
            ptr = ptr + partlength + 1;
        }

        return hostName;
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format(" %-30s %-10d %-4s %s\n", record.getHostName(), record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(), record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(), node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(), node.getType(), record.getTTL(),
                    record.getTextResult());
        }
    }

    /**
     * Creates a random ID for a DNS query
     * 
     * @return int of the ID generated.
     */
    private static int randomIDGenerator() {
        int id = new Random().nextInt(1 + Short.MAX_VALUE - Short.MIN_VALUE);
        if (!queryIDArray.contains(id)) {
            queryIDArray.add(id);
            return id;
        }
        randomIDGenerator();
        return -1;
    }

    private static byte[] createQuery(DNSNode node) {
        byte[] query = new byte[512];
        int id = randomIDGenerator();

        // Shift 8 Bits to the left to get first 8 bits
        int firstHalfID = id >>> 8;
        // Get Last 8 bytes
        int secondHalfID = id & 0xff;
        // Unique ID
        query[0] = (byte) firstHalfID;
        query[1] = (byte) secondHalfID;

        // Configure QR, Opcode, AA, TC, RD, RA, Z, RCODE
        query[2] = (byte) 0;
        query[3] = (byte) 0;
        // Set QDCOUNT
        query[4] = (byte) 0;
        query[5] = (byte) 1;
        // Set ADCOUNT
        query[6] = (byte) 0;
        query[7] = (byte) 0;
        // Set NSCOUNT
        query[8] = (byte) 0;
        query[9] = (byte) 0;
        // SET ARCOUNT
        query[10] = (byte) 0;
        query[11] = (byte) 0;

        int index = 12;
        // QNAME
        String hostName = node.getHostName();
        String[] hostNameSplit = hostName.split("\\.");

        for (String s : hostNameSplit) {
            int length = s.length();
            query[index] = (byte) length;
            index++;
            char[] characters = s.toCharArray();
            for (char c : characters) {
                query[index] = (byte) c;
                index++;
            }
        }

        query[index] = (byte) 0;
        index++;

        // QTYPE
        int qType = node.getType().getCode();
        query[index] = (byte) ((qType >>> 8) & 0xff);
        index++;
        query[index] = (byte) (qType & 0xff);
        index++;
        // QCLASS
        query[index] = (byte) 0;
        index++;
        query[index] = (byte) 1;
        index++;

        return Arrays.copyOfRange(query, 0, index);
    }
}