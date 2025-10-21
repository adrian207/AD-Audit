// M&A Audit Query Builder - Application Logic
// Author: Adrian Johnson <adrian207@gmail.com>

// Global state
let currentDatabase = '';
let currentSchema = {};
let currentQuery = '';
let currentResults = [];
let filterCount = 0;

// Initialize on page load
$(document).ready(function() {
    console.log('Query Builder initialized');
    loadTemplates();
    // Auto-connect with empty path (server will auto-detect)
    connectDatabase();
});

// Show/hide loading modal
function showLoading(message) {
    $('#loadingMessage').text(message || 'Processing...');
    $('#loadingModal').modal('show');
}

function hideLoading() {
    $('#loadingModal').modal('hide');
}

// Connect to database
function connectDatabase() {
    const dbPath = $('#dbPath').val().trim();
    
    showLoading('Connecting to database...');
    
    $.ajax({
        url: '/api/schema',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ databasePath: dbPath }),
        success: function(response) {
            hideLoading();
            if (response.success) {
                currentDatabase = response.databasePath;
                currentSchema = response.schema;
                
                // Update UI
                $('#dbStatus').text('Connected: ' + currentDatabase.split('\\').pop());
                $('#dbStatus').addClass('text-success');
                $('#dbPath').val(currentDatabase);
                
                // Populate table dropdown
                const tableSelect = $('#tableSelect');
                tableSelect.empty();
                tableSelect.append('<option value="">Select a table...</option>');
                
                const tables = Object.keys(currentSchema).sort();
                tables.forEach(table => {
                    tableSelect.append(`<option value="${table}">${table}</option>`);
                });
                
                // Show query builder
                $('#queryCard').show();
                $('#filtersCard').show();
                $('#sqlCard').show();
                
                // Update database info
                $('#tableCount').text(tables.length);
                $('#dbPathDisplay').text(currentDatabase);
                $('#dbInfoCard').show();
                
                showSuccess('Connected successfully! Found ' + tables.length + ' tables.');
            } else {
                showError('Connection failed: ' + response.error);
            }
        },
        error: function(xhr) {
            hideLoading();
            const error = xhr.responseJSON ? xhr.responseJSON.error : 'Connection failed';
            showError(error);
        }
    });
}

// Load columns for selected table
function loadColumns() {
    const table = $('#tableSelect').val();
    if (!table) return;
    
    const columns = currentSchema[table];
    const columnsList = $('#columnsList');
    columnsList.empty();
    
    columns.forEach(col => {
        const checked = 'checked'; // All checked by default
        const pkBadge = col.pk ? '<span class="badge bg-warning text-dark ms-1">PK</span>' : '';
        const notNullBadge = col.notnull ? '<span class="badge bg-info text-dark ms-1">NOT NULL</span>' : '';
        
        columnsList.append(`
            <div class="form-check">
                <input class="form-check-input column-checkbox" type="checkbox" value="${col.name}" 
                       id="col_${col.name}" ${checked} onchange="updateSQL()">
                <label class="form-check-label" for="col_${col.name}">
                    <strong>${col.name}</strong>
                    <span class="text-muted">(${col.type})</span>
                    ${pkBadge}${notNullBadge}
                </label>
            </div>
        `);
    });
    
    // Clear filters when table changes
    $('#filtersList').html('<p class="text-muted">No filters added. Click "Add Filter" to start building your WHERE clause.</p>');
    filterCount = 0;
    
    updateSQL();
}

// Select/Deselect all columns
function selectAllColumns() {
    $('.column-checkbox').prop('checked', true);
    updateSQL();
}

function deselectAllColumns() {
    $('.column-checkbox').prop('checked', false);
    updateSQL();
}

// View sample data for table
function viewSampleData() {
    const table = $('#tableSelect').val();
    if (!table) {
        showError('Please select a table first');
        return;
    }
    
    showLoading('Loading sample data...');
    
    $.ajax({
        url: '/api/sample',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ 
            table: table,
            databasePath: currentDatabase
        }),
        success: function(response) {
            hideLoading();
            if (response.success) {
                currentResults = response.data;
                displayResults(response.data);
                $('#resultsCard').show();
                $('#rowCount').text(response.data.length + ' rows (sample)');
                $('#executionTime').text('Sample data');
                
                // Scroll to results
                $('html, body').animate({
                    scrollTop: $('#resultsCard').offset().top - 100
                }, 500);
            } else {
                showError('Failed to load sample data: ' + response.error);
            }
        },
        error: function(xhr) {
            hideLoading();
            showError('Failed to load sample data');
        }
    });
}

// Add filter row
function addFilter() {
    const table = $('#tableSelect').val();
    if (!table) {
        showError('Please select a table first');
        return;
    }
    
    filterCount++;
    const columns = currentSchema[table];
    const filterId = 'filter_' + filterCount;
    
    // Build column options
    let columnOptions = '<option value="">Select field...</option>';
    columns.forEach(col => {
        columnOptions += `<option value="${col.name}">${col.name} (${col.type})</option>`;
    });
    
    const filterHtml = `
        <div class="filter-row row g-2 mb-2" id="${filterId}">
            <div class="col-md-1">
                <select class="form-select form-select-sm filter-logic" onchange="updateSQL()">
                    <option value="AND">AND</option>
                    <option value="OR">OR</option>
                </select>
            </div>
            <div class="col-md-3">
                <select class="form-select form-select-sm filter-field" onchange="updateSQL()">
                    ${columnOptions}
                </select>
            </div>
            <div class="col-md-2">
                <select class="form-select form-select-sm filter-operator" onchange="updateSQL()">
                    <option value="=">=</option>
                    <option value="!=">!=</option>
                    <option value="<">&lt;</option>
                    <option value=">">&gt;</option>
                    <option value="<=>">&lt;=</option>
                    <option value=">=">&gt;=</option>
                    <option value="LIKE">LIKE</option>
                    <option value="NOT LIKE">NOT LIKE</option>
                    <option value="IS NULL">IS NULL</option>
                    <option value="IS NOT NULL">IS NOT NULL</option>
                </select>
            </div>
            <div class="col-md-4">
                <input type="text" class="form-control form-control-sm filter-value" 
                       placeholder="Value" onkeyup="updateSQL()">
            </div>
            <div class="col-md-2">
                <button class="btn btn-sm btn-danger w-100" onclick="removeFilter('${filterId}')">
                    <i class="fas fa-times"></i> Remove
                </button>
            </div>
        </div>
    `;
    
    if ($('#filtersList p').length) {
        $('#filtersList').empty();
    }
    
    $('#filtersList').append(filterHtml);
    updateSQL();
}

// Remove filter row
function removeFilter(filterId) {
    $('#' + filterId).remove();
    if ($('.filter-row').length === 0) {
        $('#filtersList').html('<p class="text-muted">No filters added. Click "Add Filter" to start building your WHERE clause.</p>');
    }
    updateSQL();
}

// Update SQL preview
function updateSQL() {
    const table = $('#tableSelect').val();
    if (!table) {
        $('#sqlPreview code').text('-- Select a table to begin');
        return;
    }
    
    // Build SELECT clause
    const selectedColumns = [];
    $('.column-checkbox:checked').each(function() {
        selectedColumns.push('[' + $(this).val() + ']');
    });
    
    const selectClause = selectedColumns.length > 0 ? selectedColumns.join(', ') : '*';
    let sql = `SELECT ${selectClause}\nFROM [${table}]`;
    
    // Build WHERE clause
    const filters = [];
    $('.filter-row').each(function(index) {
        const logic = $(this).find('.filter-logic').val();
        const field = $(this).find('.filter-field').val();
        const operator = $(this).find('.filter-operator').val();
        const value = $(this).find('.filter-value').val();
        
        if (!field) return;
        
        if (operator === 'IS NULL' || operator === 'IS NOT NULL') {
            filters.push({ logic: logic, clause: `[${field}] ${operator}` });
        } else if (value) {
            let formattedValue;
            if (operator === 'LIKE' || operator === 'NOT LIKE') {
                formattedValue = `'%${value}%'`;
            } else if (!isNaN(value) && value !== '') {
                formattedValue = value; // Numeric value
            } else {
                formattedValue = `'${value.replace(/'/g, "''")}'`; // String value, escape quotes
            }
            filters.push({ logic: logic, clause: `[${field}] ${operator} ${formattedValue}` });
        }
    });
    
    if (filters.length > 0) {
        sql += '\nWHERE ';
        filters.forEach((filter, index) => {
            if (index === 0) {
                sql += filter.clause;
            } else {
                sql += `\n  ${filter.logic} ${filter.clause}`;
            }
        });
    }
    
    sql += '\nLIMIT 1000';
    
    currentQuery = sql;
    $('#sqlPreview code').text(sql);
}

// Execute query
function executeQuery() {
    if (!currentQuery) {
        showError('No query to execute');
        return;
    }
    
    showLoading('Executing query...');
    
    $.ajax({
        url: '/api/query',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ 
            query: currentQuery,
            databasePath: currentDatabase,
            limit: 1000
        }),
        success: function(response) {
            hideLoading();
            if (response.success) {
                currentResults = response.data;
                displayResults(response.data);
                $('#resultsCard').show();
                $('#rowCount').text(response.rowCount + ' rows');
                $('#executionTime').text('Executed in ' + response.executionTime + ' ms');
                
                showSuccess('Query executed successfully! Retrieved ' + response.rowCount + ' rows.');
                
                // Scroll to results
                $('html, body').animate({
                    scrollTop: $('#resultsCard').offset().top - 100
                }, 500);
            } else {
                showError('Query failed: ' + response.error);
            }
        },
        error: function(xhr) {
            hideLoading();
            const error = xhr.responseJSON ? xhr.responseJSON.error : 'Query execution failed';
            showError(error);
        }
    });
}

// Display results in table
function displayResults(data) {
    const resultsTable = $('#resultsTable');
    resultsTable.empty();
    
    if (data.length === 0) {
        resultsTable.html('<div class="alert alert-info m-3">No results found</div>');
        return;
    }
    
    // Build table
    const columns = Object.keys(data[0]);
    let html = '<table class="table table-striped table-hover table-sm mb-0">';
    html += '<thead class="table-dark sticky-top"><tr>';
    columns.forEach(col => html += `<th>${col}</th>`);
    html += '</tr></thead><tbody>';
    
    data.forEach(row => {
        html += '<tr>';
        columns.forEach(col => {
            const value = row[col];
            html += `<td>${value !== null ? value : '<span class="text-muted">NULL</span>'}</td>`;
        });
        html += '</tr>';
    });
    
    html += '</tbody></table>';
    resultsTable.html(html);
}

// Export to CSV
function exportCSV() {
    if (currentResults.length === 0) {
        showError('No results to export');
        return;
    }
    
    showLoading('Preparing CSV export...');
    
    $.ajax({
        url: '/api/export',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ data: currentResults }),
        xhrFields: {
            responseType: 'blob'
        },
        success: function(data, status, xhr) {
            hideLoading();
            
            // Get filename from headers or use default
            const filename = 'query_results_' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv';
            
            // Create download link
            const url = window.URL.createObjectURL(data);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showSuccess('CSV exported successfully!');
        },
        error: function() {
            hideLoading();
            showError('Export failed');
        }
    });
}

// Copy SQL to clipboard
function copySQL() {
    const sql = $('#sqlPreview code').text();
    navigator.clipboard.writeText(sql).then(function() {
        showSuccess('SQL copied to clipboard!');
    }, function() {
        showError('Failed to copy SQL');
    });
}

// Reset query builder
function resetQuery() {
    $('#tableSelect').val('');
    $('#columnsList').html('<p class="text-muted mb-0">Select a table to see available columns</p>');
    $('#filtersList').html('<p class="text-muted">No filters added. Click "Add Filter" to start building your WHERE clause.</p>');
    $('#sqlPreview code').text('-- Select a table to begin');
    $('#resultsCard').hide();
    filterCount = 0;
    currentQuery = '';
    currentResults = [];
}

// Load query templates
function loadTemplates() {
    $.ajax({
        url: '/api/templates',
        method: 'GET',
        success: function(response) {
            if (response.success) {
                displayTemplates(response.templates);
            }
        },
        error: function() {
            $('#templatesList').html('<div class="list-group-item text-danger">Failed to load templates</div>');
        }
    });
}

// Display templates
function displayTemplates(templates) {
    const templatesList = $('#templatesList');
    templatesList.empty();
    
    // Group by category
    const categories = {};
    templates.forEach(template => {
        if (!categories[template.category]) {
            categories[template.category] = [];
        }
        categories[template.category].push(template);
    });
    
    // Display by category
    Object.keys(categories).sort().forEach(category => {
        templatesList.append(`<div class="list-group-item bg-light"><strong>${category}</strong></div>`);
        
        categories[category].forEach(template => {
            const item = `
                <a href="#" class="list-group-item list-group-item-action" onclick="loadTemplate('${template.name}'); return false;">
                    <div class="d-flex w-100 justify-content-between">
                        <h6 class="mb-1">${template.name}</h6>
                    </div>
                    <p class="mb-0 small text-muted">${template.description}</p>
                </a>
            `;
            templatesList.append(item);
        });
    });
}

// Load template query
function loadTemplate(templateName) {
    $.ajax({
        url: '/api/templates',
        method: 'GET',
        success: function(response) {
            if (response.success) {
                const template = response.templates.find(t => t.name === templateName);
                if (template) {
                    currentQuery = template.query;
                    $('#sqlPreview code').text(template.query);
                    showSuccess('Template loaded: ' + template.name);
                    
                    // Scroll to SQL preview
                    $('html, body').animate({
                        scrollTop: $('#sqlCard').offset().top - 100
                    }, 500);
                }
            }
        }
    });
}

// Show success message
function showSuccess(message) {
    showToast(message, 'success');
}

// Show error message
function showError(message) {
    showToast(message, 'danger');
}

// Show toast notification
function showToast(message, type) {
    const toast = $(`
        <div class="toast align-items-center text-white bg-${type} border-0 position-fixed bottom-0 end-0 m-3" role="alert" style="z-index: 9999;">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `);
    
    $('body').append(toast);
    const bsToast = new bootstrap.Toast(toast[0], { delay: 5000 });
    bsToast.show();
    
    toast.on('hidden.bs.toast', function() {
        $(this).remove();
    });
}

