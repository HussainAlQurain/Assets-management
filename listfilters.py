
tonerscounter = 0
try:
    
    for x in toners:
        index += 1
        test = index
        tmp = x["Printer"]
        for c in range(test, len(toners)):
            if tmp == toners[c]["Printer"]:
                toners[c]["Printer"] = ''
            else:
                break;
            
except:
    pass