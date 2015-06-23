#!/usr/bin/python
# Author: Scott Pack
# Create Tickets for vulnerability remediation from Splunk to Jira


import csv, sys, urllib, re, requests, pickle, json
import jira_creds
from client import JIRA
from client import GreenHopper
import jira_queues
import datetime

jira_url = https://jira.omniture.com:443
watchers = []
label_list = []
epic_link = "EPIC NAME"

def get_priority(score):
    #Returns the letter grade and the number of days within which a patch must be deployed.
    if score < 300:
        return ("A",360)
    elif score < 2500:
        return ("B",180)
    elif score < 5000:
        return ("C",90)
    elif score < 8000:
        return ("D",60)
    else:
        return ("F",30)

def get_due_date(score):
    n = datetime.datetime.now()
    priority,date_delta = get_priority(score)
    d = datetime.timedelta(days=date_delta)

    t = n+d

    month= int(t.month)
    year = int(t.year)
    return "%s-%s-%s" % (int(t.year),int(t.month),int(t.day))

def get_target_quarter(score):
    n = datetime.datetime.now()
    priority,date_delta = get_priority(score)
    d = datetime.timedelta(days=date_delta)

    t = n+d
    
    month= int(t.month)
    year = int(t.year)
    q = 0
    if month == 12:
        year = year - 1
    if month == 12 or month <3:
        q = 1
    elif month >=3 and month <6:
        q = 2
    elif month >=6 and month < 9:
        q = 3
    elif month >=9 and month < 12:
        q = 4
    return "Q%s/%s" % (q,year)
    
     
def issue_exists(jira, project, name):
    query = "project=%s AND summary ~ \"\\\"%s\\\"\"" % (project, name)
    already_existing = jira.search_issues(query)
    if already_existing.__len__() == 0:
        return False
    else:
        return True

def label_issue(jira, issue, score):
    quarter = get_target_quarter(score)
    issue.add_field_value("labels",quarter)
    for label in label_list:
        issue.add_field_value("labels",label)

def create_issue(jira, gh, key_string, summary_string, description_string, score):
    print >> sys.stderr, "Creating an issue for %s - Score %s" % (summary_string, score)
    print >> sys.stderr, "Due date will be %s" % get_due_date(score)
    desc_addendum = "\n\nVulnerability Score: %s\nDue Date: %s" % (score, due)
    due = get_due_date(score)
    issue = ""
    try:
        issue = jira.create_issue(
            project={'key':key_string}, 
            summary=summary_string,
            description=description_string+desc_addendum, 
            issuetype={'name':"Request"},
            duedate=due,
            )
        print >> sys.stderr, "Jira Issue Creation Return"
        print >> sys.stderr, issue
    except:
        try:
            issue = jira.create_issue(
                project={'key':key_string},
                summary=summary_string,
                description=description_string,
                issuetype={'name':"Task"},
                duedate=due,
                )
            print >> sys.stderr, "Jira Issue Creation Return"
            print >> sys.stderr, issue
        except:
            print >> sys.stderr, "Uhoh, something bad happened when trying to create a request or task"
            return None
  
    label_issue(jira, issue, score)

    gh.add_issues_to_epic(epic_link,[str(issue)])

    #Delay adding watchers to not spam them quite so much
    for w in watchers:
        jira.add_watcher(issue,w)

    for w in jira_queues.get_watchers(key_string):
        jira.add_watcher(issue,w)

    return str(issue)

def generate_ticket(jira,gh,ips,desc,sol,name,score):
    print >> sys.stderr, "Generating ticket"
    print >> sys.stderr, "%s, %s, %s, %s" % (ips,desc,sol,name)
    #ip_list description solution name    
    queue = jira_queues.get_queue(sol)
    full_desc = desc

    if sol is None:
        return {"solution":sol,"queue":"NONE","name":name,"success":"false","message":"No Service To Queue Mapping"}
    if issue_exists(jira,queue,name):
        return {"solution":sol,"queue":queue,"name":name,"success":"false","message":"An issue with that name already exists in the project"}

    ret = create_issue(jira,gh,queue,name,full_desc, score)
    print >> sys.stderr, "Jira returned %s" % str(ret)
    if ret is not None:
        return {"solution":sol,"queue":queue,"name":name,"success":"true","message":"Issue %s created" % str(ret)} 
    else:
        return {"solution":sol,"queue":queue,"name":name,"success":"false","message":"Jira returned None"}

class Reader:
    def __init__(self, buf, filename = None):
        self.buf = buf
        if filename is not None:
            self.log = open(filename, 'w')
        else:
            self.log = None

    def __iter__(self):
        return self

    def next(self):
        return self.readline()

    def readline(self):
        line = self.buf.readline()

        if not line:
            raise StopIteration

        # Log to a file if one is present
        if self.log is not None:
            self.log.write(line)
            self.log.flush()

        # Return to the caller
        return line

def output_results(results, mvdelim = '\n', output = sys.stdout):
    """Given a list of dictionaries, each representing
    a single result, and an optional list of fields,
    output those results to stdout for consumption by the
    Splunk pipeline"""

    # We collect all the unique field names, as well as 
    # convert all multivalue keys to the right form
    fields = set()
    for result in results:    
        for key in result.keys():
            if(isinstance(result[key], list)):
                result['__mv_' + key] = encode_mv(result[key])
                result[key] = mvdelim.join(result[key])
        fields.update(result.keys())

    # convert the fields into a list and create a CSV writer
    # to output to stdout
    fields = sorted(list(fields))
    writer = csv.DictWriter(output, fields)

    # Write out the fields, and then the actual results
    writer.writerow(dict(zip(fields, fields)))
    writer.writerows(results)

def read_input(buf, has_header = True):
    """Read the input from the given buffer (or stdin if no buffer)
    is supplied. An optional header may be present as well"""

    # Use stdin if there is no supplied buffer
    if buf == None:
        buf = sys.stdin

    # Attempt to read a header if necessary
    header = {}
    if has_header:
        # Until we get a blank line, read "attr:val" lines, 
        # setting the values in 'header'
        last_attr = None
        while True:
            line = buf.readline()

            # remove lastcharacter (which is a newline)
            line = line[:-1] 

            # When we encounter a newline, we are done with the header
            if len(line) == 0:
                break

            colon = line.find(':')

            # If we can't find a colon, then it might be that we are
            # on a new line, and it belongs to the previous attribute
            if colon < 0:
                if last_attr:
                    header[last_attr] = header[last_attr] + '\n' + urllib.unquote(line)
                else:
                    continue

            # extract it and set value in settings
            last_attr = attr = line[:colon]
            val  = urllib.unquote(line[colon+1:])
            header[attr] = val

    return buf, header



def main(argv):
    print >> sys.stderr, "Starting Jira Ticket Creation"
    stdin_wrapper = Reader(sys.stdin)
    buf, settings = read_input(stdin_wrapper, has_header = True)

    print >> sys.stderr, "GenTickets: " + str(buf)
    print >> sys.stderr, "GenTickets: " + str(settings)
    print >> sys.stderr, "GenTickets: " + str(argv)

    jira = JIRA(options={'server': jira_url},basic_auth=(jira_creds.username,jira_creds.password))
    gh = GreenHopper(options={'server': jira_url},basic_auth=(jira_creds.username,jira_creds.password))

    events = csv.DictReader(buf)
    results = []
    print >> sys.stderr, "Entering generator loop"
    print >> sys.stderr, "Fields:"
    print >> sys.stderr, argv[1]
    print >> sys.stderr, argv[2]
    print >> sys.stderr, argv[3]
    print >> sys.stderr, argv[4]
    print >> sys.stderr, argv[5]

    for event in events:
       ips = event[argv[1]]
       desc = event[argv[2]]
       sol = event[argv[3]]
       name = event[argv[4]]
       score = event[argv[5]]
       res = generate_ticket(jira,gh,ips,desc,sol,name, score)
       print >> sys.stderr, "Ticket generate returned: %s" % str(res)
       results.append(res)
      
    output_results(results)

if __name__ == "__main__":
    try:
	main(sys.argv)
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stderr)


