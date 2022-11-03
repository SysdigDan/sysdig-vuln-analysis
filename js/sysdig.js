// https://github.com/d3/d3-scale-chromatic
dc.config.defaultColors(d3.schemePaired)


var severityChart = new dc.PieChart('#severity-chart');
var exploitableChart = new dc.PieChart("#exploitable-chart")
var imageChart = new dc.RowChart("#image-chart");
var packageChart = new dc.RowChart("#package-chart");
var vulnCount = new dc.DataCount('.dc-data-count');
var vulnTable = new dc.DataTable('.dc-data-table');
var kuberentesChart = new dc.SunburstChart("#kuberentes-chart");
var searchWidget = new dc.TextFilterWidget("#search-widget")

function loadCsv(path) {
    $('#content').show();

    d3.csv("data/sysdig-example.csv").then(function (vulnerabilities) {
        const dateFormatSpecifier = '%d/%m/%Y';
        const dateFormat = d3.timeFormat(dateFormatSpecifier);
        const dateFormatParser = d3.timeParse(dateFormatSpecifier);
        const numberFormat = d3.format('.2f');
        const topImages = 10;
        const topPackages = 10;

        vulnerabilities.forEach(function (d) {
            d.VulnID = d['Vulnerability ID'];
            d.Image = d['Image'];
            d.Severity = d['Severity'];
            d.Package = d['Package name'] + ':' + d['Package version'];
            d.Cluster = d['K8S cluster name'];
            d.Namespace = d['K8S namespace name'];
            d.Workload = d['K8S workload name'];
            d.PublicExploit = d['Public Exploit'];

        });

        var ndx = crossfilter(vulnerabilities);
        var all = ndx.groupAll();

        // Create dimensions
        var vulnID = ndx.dimension(function (d) { return d.VulnID; });
        var vulnGroup = vulnID.group().reduceCount();

        var image = ndx.dimension(function (d) { return d.Image; });
        var imageGroup = image.group().reduceCount();

        var exploitable = ndx.dimension(function (d) { return d.PublicExploit; });
        var exploitableGroup = exploitable.group().reduceCount();

        var severity = ndx.dimension(function (d) { return d.Severity; });
        var severityGroup = severity.group().reduceCount();

        var package = ndx.dimension(function (d) { return d.Package; });
        var packageGroup = package.group();

        var kuberentesDimension = ndx.dimension(function (d) {
            return [d.Cluster, d.Namespace, d.Workload];
        });
        var kuberentesGroup = kuberentesDimension.group();

        searchWidget
            .dimension(vulnID);

        exploitableChart
            .width(300)
            .height(400)
            .slicesCap(4)
            // .innerRadius(50)
            // .externalLabels(50)
            .externalRadiusPadding(50)
            .drawPaths(false)
            .legend(dc.legend().x(20).y(20).itemHeight(13).gap(10))
            .dimension(exploitable)
            .group(exploitableGroup);

        severityChart
            .width(300)
            .height(400)
            .slicesCap(4)
            // .innerRadius(50)
            // .externalLabels(50)
            .externalRadiusPadding(50)
            .drawPaths(false)
            .legend(dc.legend().x(20).y(20).itemHeight(13).gap(10))
            .dimension(severity)
            .group(severityGroup);

        kuberentesChart
            .width(600)
            .height(400)
            .innerRadius(100)
            .dimension(kuberentesDimension)
            .group(kuberentesGroup)
            // .legend(dc.legend().x(400).y(120).itemHeight(13).gap(10))
            .ringSizes(kuberentesChart.defaultRingSizes());

        imageChart
            .width(1200)
            .height(300)
            .x(d3.scaleLinear().domain([6, 20]))
            .elasticX(true)
            .dimension(image)
            .group(imageGroup)
            .data(function (group) {
                return group.top(topImages);
            });

        packageChart
            .width(1200)
            .height(300)
            .x(d3.scaleLinear().domain([6, 20]))
            .elasticX(true)
            .dimension(package)
            .group(packageGroup)
            .data(function (group) {
                return group.top(topImages);
            });

        vulnCount
            .groupAll(all)
            .html({
                some:
                    '<strong>%filter-count</strong> selected out of <strong>%total-count</strong> records' +
                    " | <a href='javascript:dc.filterAll(); dc.redrawAll();'>Reset All</a>",
                all: 'All records selected. Please click on the graph to apply filters.',
            })
            .crossfilter(ndx)
            .groupAll(all);

        vulnTable
            .width(1200)
            .dimension(vulnID)
            // .group(function (d) { return d.Severity; })
            .size(Infinity)
            .columns([
                {
                    label: 'CVE',
                    format: function (d) {
                        return "<a href=" + d['Vuln link'] + ">" + d['Vulnerability ID'] + "</a>";
                    }
                },
                'Severity',
                {
                    label: 'Publish Date',
                    format: function (d) {
                        return d['Vuln Publish date'];
                    }
                },
                'Image',
                {
                    label: 'Package',
                    format: function (d) {
                        return d['Package name'] + ":" + d['Package version'];
                    }
                },
                {
                    label: 'Public Exploit',
                    format: function (d) {
                        return d.PublicExploit;
                    }
                },
                // 'Cluster',
                // 'Namespace',
                // 'Workload',
            ])
            .sortBy(function (d) { return d.Severity; })
            .order(d3.ascending)
            .on('renderlet', function (table) {
                table.selectAll('.dc-table-group').classed('info', true);
            });

        d3.select('#download')
            .on('click', function () {
                var data = vulnID.top(Infinity);
                var blob = new Blob([d3.csvFormat(data)], { type: "text/csv;charset=utf-8" });
                saveAs(blob, 'sysdig_filtered_results.csv');
            });

        dc.renderAll();
    });
}

function readCsvFromFile(evt) {
    if (window.File && window.FileReader && window.FileList && window.Blob) {
        var f = evt.target.files[0];
        var reader = new FileReader();
        reader.onload = (function (theFile) {

            return function (e) {
                loadCsv(e.target.result);
            };
        })(f);
        reader.readAsDataURL(f);
    } else {
        alert('The File APIs are not fully supported in this browser.');
    }
}

function titleCase(str) {
    var newstr = str.split(" ");
    for (i = 0; i < newstr.length; i++) {
        var copy = newstr[i].substring(1).toLowerCase();
        newstr[i] = newstr[i][0].toUpperCase() + copy;
    }
    newstr = newstr.join(" ");
    return newstr;
}

$('#csvFile').on('change', readCsvFromFile);
$('#csvFile').on('click', function () { $(this).val("") });

