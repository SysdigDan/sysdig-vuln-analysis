// https://github.com/d3/d3-scale-chromatic
var _schemeSysdig = [
    '#00abc7', '#00bdd3', '#65cada', '#9cdee8', '#cfeef3'];

dc.config.defaultColors(_schemeSysdig)

var severityChart = new dc.PieChart('#severity-chart');
var exploitableChart = new dc.PieChart("#exploitable-chart")
var fixAvailableChart = new dc.PieChart('#fix-chart');
var imageChart = new dc.RowChart("#image-chart");
var packageChart = new dc.RowChart("#package-chart");
var vulnCount = new dc.DataCount('.dc-data-count');
var vulnTable = new dc.DataTable('.dc-data-table');
var kuberentesChart = new dc.SunburstChart("#kuberentes-chart");
var searchWidget = new dc.TextFilterWidget("#search")

function loadCsv(path) {

    // $('#content').show();

    d3.csv(path).then(function (vulnerabilities) {
        const dateFormatSpecifier = '%d/%m/%Y';
        // const dateFormat = d3.timeFormat(dateFormatSpecifier);
        // const dateFormatParser = d3.timeParse(dateFormatSpecifier);
        // const numberFormat = d3.format('.2f');
        const topImages = 10;
        const topPackages = 10;
        const topRows = 1000;

        vulnerabilities.forEach(function (d) {
            d.VulnID = d['Vulnerability ID'];
            d.Image = d['Image'];
            d.Severity = d['Severity'];
            if (d.Severity == 'Critical') {
                d.SeveritySort = 1;
            } else if (d.Severity == 'High') {
                d.SeveritySort = 2;
            } else if (d.Severity == 'Medium') {
                d.SeveritySort = 3;
            } else if (d.Severity == 'Low') {
                d.SeveritySort = 4;
            } else {
                d.SeveritySort = 5;
            }
            if (d['Vuln Fix date']) {
                d.FixAvailable = "true"
            } else {
                d.FixAvailable = "false"
            }
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
        var exploitableGroup = exploitable.group();

        var severity = ndx.dimension(function (d) { return d.Severity; });
        var severityGroup = severity.group();

        var fixAvailable = ndx.dimension(function (d) { return d.FixAvailable; });
        var fixAvailableGroup = fixAvailable.group();

        var package = ndx.dimension(function (d) { return d.Package; });
        var packageGroup = package.group();

        var kuberentesDimension = ndx.dimension(function (d) {
            return [d.Cluster, d.Namespace, d.Workload, d.VulnID];
        });
        var kuberentesGroup = kuberentesDimension.group();

        var vulncount = vulnGroup.all().filter(kv => kv.value).length;
        d3.select("#vulncount").text(vulncount);

        criticalpkgs = packageGroup.all().filter(kv => kv.value).length;
        console.log(criticalpkgs);

        searchWidget
            .placeHolder("CVE Filter")
            .dimension(vulnID);

        severityChart
            .width(300)
            .height(300)
            .slicesCap(5)
            .innerRadius(30)
            .externalRadiusPadding(15)
            .drawPaths(false)
            .colors(d3.scaleOrdinal()
                .domain(["Critical", "High", "Medium", "Low", "Negligible"])
                .range(["#AE44C5", "#EE635E", "#FA8C16", "#F6CA09", "#91A7B3"])
                )
            .label(function (d) {
                return d.key + ' ( ' + d.value + ' ) ';
            })
            // .legend(dc.legend()
            //     .highlightSelected(true)
            //     .legendText(function (d) { return d.name + ' | ' + d.data; })
            //     .legendWidth(270)
            //     .x(5)
            //     .y(240)
            //     .itemHeight(15)
            //     .gap(15)
            //     .horizontal(true)
            //     .autoItemWidth(true))
            .dimension(severity)
            .group(severityGroup);

        exploitableChart
            .width(300)
            .height(300)
            .slicesCap(2)
            .innerRadius(30)
            .externalRadiusPadding(15)
            .drawPaths(false)
            .colors(d3.scaleOrdinal()
                .domain(["true", "false"])
                .range(["#EC7063", "#52BE80"])
            )
            .on('renderlet.a', function (chart) {
                chart.selectAll('text.pie-slice').text(function (d) {
                    return d.data.key + ' ( ' + dc.utils.printSingleValue((d.endAngle - d.startAngle) / (2 * Math.PI) * 100) + '% )';
                });
            })
            // .legend(dc.legend()
            //     .highlightSelected(true)
            //     .legendText(function (d) { return d.name + ' | ' + d.data; })
            //     .legendWidth(15)
            //     .y(15)
            //     .itemHeight(15)
            //     .gap(15)
            //     .horizontal(false)
            //     .autoItemWidth(true))
            .dimension(exploitable)
            .group(exploitableGroup);

        fixAvailableChart
            .width(300)
            .height(300)
            .slicesCap(2)
            .innerRadius(30)
            .externalRadiusPadding(15)
            .drawPaths(false)
            .colors(d3.scaleOrdinal()
                .domain(["true", "false"])
                .range(["#52BE80", "#EC7063"])
            )
            .on('renderlet.a', function (chart) {
                chart.selectAll('text.pie-slice').text(function (d) {
                    return d.data.key + ' ( ' + dc.utils.printSingleValue((d.endAngle - d.startAngle) / (2 * Math.PI) * 100) + '% )';
                })
            })
            // .legend(dc.legend()
            //     .highlightSelected(true)
            //     .legendText(function (d) { return d.name + ' | ' + d.data; })
            //     .legendWidth(270)
            //     .x(5)
            //     .y(240)
            //     .itemHeight(15)
            //     .gap(15)
            //     .horizontal(true)
            //     .autoItemWidth(true))
            .dimension(fixAvailable)
            .group(fixAvailableGroup);

        kuberentesChart
            .width(600)
            .height(500)
            .innerRadius(100)
            .dimension(kuberentesDimension)
            .group(kuberentesGroup)
            // .legend(dc.legend().x(400).y(120).itemHeight(13).gap(10))
            .ringSizes(kuberentesChart.defaultRingSizes());

        imageChart
            .width(1100)
            .height(380)
            .x(d3.scaleLinear().domain([6, 20]))
            .elasticX(true)
            .dimension(image)
            .group(imageGroup)
            .label(function (d) {
                return d.key + ' ( ' + d.value + ' ) ';
            })
            .data(function (group) {
                return group.top(topImages);
            });

        packageChart
            .width(1050)
            .height(380)
            .x(d3.scaleLinear().domain([6, 20]))
            .elasticX(true)
            .dimension(package)
            .group(packageGroup)
            .label(function (d) {
                return d.key + ' ( ' + d.value + ' ) ';
            })
            .data(function (group) {
                return group.top(topPackages);
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
            .dimension(severity)
            .data(function (group) {
                return group.top(topRows);
            })
            .size(topRows)
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
            .sortBy(function (d) {
                return d.SeveritySort; })
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
        reader.onload = (function () {
            return function (e) {
                loadCsv(e.target.result);
            };
        })(f);
        reader.readAsDataURL(f);
    } else {
        alert('The File APIs are not fully supported in this browser.');
    }
}

$('#csvFile').on('change', readCsvFromFile);
$('#csvFile').on('click', function () { $(this).val("") });

