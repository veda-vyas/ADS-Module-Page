import csv

unique_reasons = {}
reasons_count = 0
positive_reasons_count = 0
negative_reasons_count = 0
with open('exams_feedback.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile,delimiter=',')
    with open('pos.csv', 'w') as positive:
        positive_file = csv.writer(positive,delimiter=',')
        with open('neg.csv', 'w') as negative:
            negative_file = csv.writer(negative,delimiter=',')

            for line in csvreader:
                for reason in line:
                    if reason.lower() not in unique_reasons:
                        print reason
                        unique_reasons[reason.lower()] = raw_input("Enter sentiment for above reason: ")
                        reasons_count+=1
                    else:
                        print reason

                    if unique_reasons[reason.lower()] == 'n':
                        negative_file.writerow([reason])
                        negative_reasons_count+=1
                    if unique_reasons[reason.lower()] == 'p':
                        positive_file.writerow([reason])
                        positive_reasons_count+=1

                    print reason, unique_reasons[reason.lower()]
                    print "\n"

                    # if reasons_count == 5:
                    #     print unique_reasons
                    #     exit(0)
print reasons_count, positive_reasons_count, negative_reasons_count
