class histogram(dict):
    """ Manage a histogram, which is really a dictionary where the keys
    are the items being counted and the values are the counts."""
    def __init__(self):
        pass
    

    def add(self,a,count=1):
        self[a] = self.get(a,0) + count

    def average(self):
        """ Return the average number of counts """
        return sum(self.values()) / self.items()

    def add_array(self,ary):
        """ Adds each element of array [ary] to the histogram."""
        for a in ary:
            self.add(a)

    def add_array_unique(self,ary):
        """ Adds each element of array [ary] to the histogram only once!."""
        for a in set(ary):
            self.add(a)

    def sortedValues(self):
        """Returns a sorted list of tuples where the element is the value
        and the second element is the count."""
        return sorted(self.iteritems())

    def unique_names(self):
        return self.keys()

    def unique_count(self):
        return len(self.keys())

    def total_names(self):
        return self.items()

    def total_count(self):
        return sum(self.values())

    def max_count(self):
        return max(self.values())

    def names_for_value(self,value):
        return [k for k in self.keys() if self[k]==value]

    def topn(self,n=-1):
        """Returns a sorted list of [(count1,[item,item]),(count2,[item,item])]"""
        r = sorted(set(self.values()))
        r.reverse()
        ret = []
        for count in r[0:n]:
            ret.append( (count,sorted(self.names_for_value(count))))
        return ret

    def print_topn(self,topn=topn,func=False,title=""):
        print(title)
        print("  Rank     Count     Value(s):")
        print("  ============================")
        rank = 1
        total_count = 0
        for (count,vals) in topn:
            for val in vals:
                fout = ""
                if func: fout = func(val)
                if val==vals[0]:
                    srank = "%5d" % rank
                else:
                    srank = "%5s" % ""
                print("  %s   %7d      %s %s" % (srank,count,val,fout))
                total_count += count 
                rank += 1
        print("")
        total = sum(self.values())
        print("Total items printed: %d" % total)
        if total-total_count>0:
            print("Values not printed: %d " % (total-total_count))

    def print_top(self,n=-1,func=False,title=""):
        if(n!=-1): print("top %d " % (n))
        topn = self.topn(n)
        self.print_topn(func=func,title=title,topn=topn)

    def print_info(self,n=-1):
        print("total count:              ",self.total_count())
        print("unique count:             ",self.unique_count())
        print("")
        self.print_top(n=n)

    def filter_more(self,n):
        """ Return the names that have counts equal to or greater than n."""
        return [k for k in self.keys() if self[k]>=n]
    
    def make_graph(self, figureTitle='Bargraph', binTitle='',
                   countTitle='Count', saveas='Barchart',
                   reverse=False,horizontal=False,
                   sortValues=False,
                   backend=None): 
        """ Creates a barchart from the histogram and saves it to disk.
        Default sort is by Key, set sortKey=False to sort by value.
        Other options for figureTitle, x-axis title, y-axis title, and the name to save the
        figure as can be passed in. """

        import matplotlib
        if backend and matplotlib.get_backend()!=backend:
            matplotlib.use(backend)
        import matplotlib.pyplot as plot
        import numpy as np

        # we need to define a new figure each time the function is
        # called, or every 'graph' will simply be drawn on top of the
        # previous one.
        # make the figure tall and skinny

        #w,h = plot.figaspect(1.75)
        #fig = plot.figure(figsize=(w,h))
        fig = plot.figure()

        # arguments to add_axes are in fractions of figure width and
        # height. these values actually take away from the area
        # available to the graph. so for example your 1st and 3rd
        # values must sum up to <= 1.0 or your graph will run off the
        # edge of your image.
        ax = fig.add_axes([0.25, 0.1, 0.7, 0.8])

        # sort according to the order requested by the user.
        vals = self.sortedValues()

        if sortValues:
            def f2(a,b):
                if a[1] < b[1]: return -1
                return +1
            vals.sort(f2)

        if reverse: vals.reverse()

        names  = [x[0] for x in vals]
        counts = [x[1] for x in vals]

        numbins = len(vals)
        barHeight = 0.6

        #set the location and labels of the x-axis ticks (our
        #histogram key values), add title and axis labels. 

        # it is utterly ridiculous that we have to set this, but if we
        # do not then the edge bar gets cut off from the graph.
        plot.ylim(ymax=(barHeight*1.5*numbins)+(1.5*barHeight/2)) 
        plot.title(figureTitle)

        # Make the font small and the xticks vertical
        for label in ax.yaxis.get_ticklabels():
            # label is a Text instance
            label.set_fontsize(6)

        for label in ax.xaxis.get_ticklabels():
            label.set_fontsize(7)

        # set the font sizes for the axis labels
        ax.xaxis.get_label().set_fontsize(8.5)
        ax.yaxis.get_label().set_fontsize(8.5)
        
        # create and save the graph
        if horizontal:
            plot.ylabel(binTitle)
            plot.xlabel(countTitle)
            plot.yticks(np.arange(numbins)+1.5*barHeight/2, names)
            rects = plot.barh(bottom=np.arange(numbins)+1.5*barHeight/2,
                              width=counts,
                              height=barHeight,align='center')
        else:
            plot.xlabel(binTitle)
            plot.ylabel(countTitle)
            plot.xticks(np.arange(numbins)+1.5*barHeight/2, names)
            rects = plot.bar(left=np.arange(numbins)+1.5*barHeight/2,
                             height=counts,
                             width=barHeight,
                             align='center')

        # add text labels at the end of each bar with the numeric 
        # total for that bar. 
        #for rect in rects:
        #    length = rect.get_width()
        #    plot.text(1.05*length, rect.get_y()+rect.get_height()/2.,
        #              '%d'%int(length), size='9')
        plot.savefig(saveas + '.pdf', format='pdf')


if(__name__=='__main__'):
    print("Demonstrate a simple histogram with print and graph output")
    j = histogram()
    j.add('apples')
    j.add('apples')
    j.add('apples')
    j.add('apples')
    j.add('apples')
    j.add('apples')
    j.add('kiwi',3)
    j.add('oranges')
    j.add('oranges')
    j.add('oranges')
    j.add('oranges')
    j.add('banana')
    j.add('cacao')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    j.add('dragonfruit')
    # optionally, make graphs. if so, make sure to import graphy.py
    j.make_graph(saveas='histogram_demo1',reverse=False,sortValues=True,horizontal=True)
    j.print_info(1000)
    print("Histogram test routine...")

    from datetime import date
    import time
    j = histogram()
    j.add(date.fromtimestamp(time.time()),4)
    j.add(date(2005,3,1))
    j.print_info(100)
    j.make_graph(saveas='histogram_demo2')

    
