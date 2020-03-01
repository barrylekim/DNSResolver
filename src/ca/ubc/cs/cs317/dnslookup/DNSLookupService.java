package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.util.Arrays;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.io.DataOutputStream;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

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
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
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
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
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
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
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
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
        // TODO To be completed by the student

        byte[] query = createQuery(node);
        System.out.println(query);
        DatagramPacket toSend = new DatagramPacket(query, query.length, rootServer, DEFAULT_DNS_PORT);
        try{
            socket.send(toSend);
            System.out.println("Sent");
        } catch (Exception e){
            System.out.println("Error");
        }
        // byte[] response =  new byte[512];
        // DatagramPacket received = new DatagramPacket(response, response.length);
        // try{
        //     socket.receive(received);
        // } catch (Exception e) {
        //     System.out.println("Error");
        // }


        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        // byte[] query = createQuery(node);
        // DatagramPacket toSend = new DatagramPacket(query, query.length, rootServer, DEFAULT_DNS_PORT);
        // try{
        //     socket.send(toSend);
        // } catch (Exception e){
        //     System.out.println("Error");
        // }
        // byte[] response =  new byte[512];
        // DatagramPacket received = new DatagramPacket(response, response.length);
        // try{
        //     socket.receive(received);
        // } catch (Exception e) {
        //     System.out.println("Error");
        // }

    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

    /**
     * Creates a random ID for a DNS query
     * 
     * @return int of the ID generated.
     */
    private static int randomIDGenerator() {
        return new Random().nextInt(1 + Short.MAX_VALUE - Short.MIN_VALUE);
    }

    private static byte[] createQuery(DNSNode node) {
        byte[] query = new byte[512];
        int id = randomIDGenerator();
        System.out.println(id);

        // Shift 8 Bits to the left to get first 8 bits
        int firstHalfID = id >>> 8;
        // Get Last 8 bytes
        int secondHalfID = id & 0xff;
        //Unique ID 
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
        //Set NSCOUNT
        query[8] = (byte) 0;
        query[9] = (byte) 0;
        //SET ARCOUNT 
        query[10] = (byte) 0;
        query[11] = (byte) 0;

        int index = 12;
        // QNAME
        String hostName = node.getHostName();
        String[] hostNameSplit = hostName.split("\\.");
        System.out.println(hostNameSplit.length);
        
        for (String s: hostNameSplit){
            int length = s.length();
            System.out.println("Length " + length);
            query[index] = (byte) length;
            index++;
            char[] characters = s.toCharArray();
            for (char c: characters){
                System.out.println("Characters " + c);
                System.out.println((byte) c);
                query[index] = (byte) c;
                System.out.println(index);
                index++;
            }
        }
        System.out.println(node.getHostName());
        
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

        return query;
    }
}
