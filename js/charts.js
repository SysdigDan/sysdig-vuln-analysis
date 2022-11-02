function loadCsv(path) {
    const chartGroup = new dc.ChartGroup();

    // ### Create Chart Objects
    const severityChart = new dc.PieChart('#severity-chart', chartGroup);
    const imagesChart = new dc.RowChart('#images-chart', chartGroup);
    const vulnCount = new dc.DataCount('.dc-data-count', chartGroup);
    const vulnTable = new dc.DataTable('.dc-data-table', chartGroup);

    $('#content').show();

    d3.csv(path).then(data => {
        const dateFormatSpecifier = '%d/%m/%Y';
        const dateFormat = d3.timeFormat(dateFormatSpecifier);
        const dateFormatParser = d3.timeParse(dateFormatSpecifier);
        const numberFormat = d3.format('.2f');
        const totalWidth = 990;

        data.forEach(d => {
            d.pubDate = dateFormatParser(d['Vuln Publish date']);
            d.severity = d['Severity'];
            d.images = d['Image'];
        });

        //### Create Crossfilter Dimensions and Groups
        const ndx = crossfilter(data);
        const all = ndx.groupAll();

        // Create date dimensions
        const dateDimension = ndx.dimension(d => d.pubDate);

        // Create severity dimension
        const severity = ndx.dimension(d => d.severity);
        const severityGroup = severity.group();

        // Create images dimension
        const images = ndx.dimension(d => d.images);
        const imagesGroup = images.group();

        severityChart /* dc.pieChart('#severity-chart', 'chartGroup') */
            .configure({
                width: totalWidth / 2.1,
                height: 300,
            })
            .dataProvider(
                new dc.CFSimpleAdapter({
                    dimension: severity,
                    group: severityGroup
                })
            );

        imagesChart /* dc.rowChart('#image-chart', 'chartGroup') */
            .configure({
                width: totalWidth / 2.1,
                height: 300,
                elasticX: true
            })
            .configure({
                // (_optional_) render horizontal grid lines, `default=false`
                renderHorizontalGridLines: true,
                // (_optional_) render vertical grid lines, `default=false`
                renderVerticalGridLines: true
            })
            .dataProvider(
                new dc.CFSimpleAdapter({
                    dimension: images,
                    group: imagesGroup,
                })
            )
            .margins({ top: 20, left: 10, right: 10, bottom: 20 });

        vulnCount /* dc.dataCount('.dc-data-count', 'chartGroup'); */
            .configure({
                // (_optional_) `.html` sets different html when some records or all records are selected.
                // `.html` replaces everything in the anchor with the html given using the following function.
                // `%filter-count` and `%total-count` are replaced with the values obtained.
                html: {
                    some:
                        '<strong>%filter-count</strong> selected out of <strong>%total-count</strong> records' +
                        " | <a href='javascript:chartGroup.filterAll(); chartGroup.redrawAll();'>Reset All</a>",
                    all: 'All records selected. Please click on the graph to apply filters.',
                },
            })
            .crossfilter(ndx)
            .groupAll(all);

        vulnTable /* dc.dataTable('.dc-data-table', 'chartGroup') */
            .configure({
                size: Infinity,
                columns: [
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
                ],
                sortBy: d => d.Severity,
                order: d3.ascending,
            })
            .dataProvider(
                new dc.CFSimpleAdapter({
                    dimension: dateDimension,
                })
            )
            .on('renderlet', table => {
                table.selectAll('.dc-table-group').classed('info', true);
            });

        //#### Rendering
        chartGroup.renderAll();
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
