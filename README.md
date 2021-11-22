# <center> CS 3640: Introduction to Networks and Their Applications </center>
## <center> Assignment 4: Web Intelligence Gathering [16 points] </center>
<center> Released on: Nov 16th | Due on: Dec 9th 11:59pm</center>
<center> <b> ** There are NO LATE DAYS for this assignment ** </b> </center>
<hr>

<h3> Learning goals </h3>

In this assignment, you will work with Scapy, a popular and powerful Python packet manipulation library, to gather
information about specific webservers. Specifically, you will run DNS queries to obtain the IP addresses associated
with a webserver, use these addresses to establish a TCP connection with the server, send a GET request to the server,
and record the path taken by your packets to reach this server.

In addition to learning about how TCP, DNS, HTTP, and ICMP work, you will also develop the ability to:

- create custom packets using Python
- send, receive, and parse these packets using Python

<hr> 

### Assignment requirements
You will need to use a Linux environment to complete this assignment. I recommend that you use a VM set up with the
Ubuntu 20.04 image. You can download Oracle's VirtualBox <a href="https://www.virtualbox.org/"> here </a> and an Ubuntu 
20.04 image <a href="https://releases.ubuntu.com/20.04/"> here </a>.

<b> Important: We will not be able to effectively provide support or grade the assignments of students who do not use 
Linux. </b>

<hr> 

### Assignment overview
There are three classes you will need to implement: `DNSProber`, `HTTPProber`, and `RouteProber`. These are contained
in the `DNSProbes.py`, `HTTPProbes.py`, and `TraceRouteProbes.py` files. Instructions are provided in each method to
be implemented.

You are to use <a href="https://scapy.readthedocs.io/en/latest/introduction.html#about-scapy"> Scapy </a> to complete
this assignment. You will find the functions that can help you complete each class already included in the imports.
You may also use other functions belonging to the Scapy library if you prefer.

<hr>

### Evaluation and submission
For this assignment, you will submit 4 files: 
- completed versions of `DNSProbes.py`, `HTTPProbes.py`, and `TraceRouteProbes.py`.
- a complete `sources.md` file in which you list a link to your **private** GitHub repository, your team's credit reel,
and links to all the resources used to help you complete this assignment.

#### Submitted program [14 points]
We will evaluate the correctness of your work with tests to a variety of domains. Points will be allocated as follows.

- Working `DNSProber`: 4 points.
  - Correctly crafting and sending DNS query [2 points].
  - Correctly parsing and saving DNS response [2 points].
- Working `RouteProber`: 4 points.
  - Correctly crafting and sending all ICMP packets [2 points].
  - Correctly parsing and saving ICMP responses [2 points].
- Working `HTTPProber`: 6 points.
  - Correctly completing TCP handshake [2 points].
  - Correctly crafting HTTP GET request [1 point].
  - Correctly processing HTTP responses and saving content [2 points].
  - Correctly closing TCP connection [1 point].

#### sources.md [1 point]
- A high-quality credit reel and accurate citations in `sources.md`.

#### Individual assessment [1 point]
- Submit a complete and [meaningful evaluation](https://forms.office.com/r/CQHTYXXvMd) of all your team-mates. [1 
point]

<hr>

### Important dates 
- **Release date:** Nov 16th, 2021
- **Group declaration date:** Nov 23rd, 2021 (11:59pm). *One member* from each group should send a message on ICON to 
- Daniyal, me, and the other teammates letting us know that you will be working together. If you are not part of any 
declared group by this point, we will assume that you will be working alone. I will allow some in-class time to 
facilitate group formation. You may also find it helpful to announce group openings on Piazza. Groups may have no more 
than 5 members (3 is recommended).

- **Due date:** Dec 9th, 2021 (11:59pm). Submission is due on ICON. The credit reel in each part of this assignment must 
clearly indicate the group members and their contributions to discussions and the submitted work. Only one 
submission will be graded for each group -- if multiple submissions are received, only the last submission will be 
graded. 
**No late submissions will be accepted for this assignment!**

- **Peer-assessment due date:** Dec 9th, 2021 (11:59pm). 
**No late submissions will be accepted for this assignment!**
