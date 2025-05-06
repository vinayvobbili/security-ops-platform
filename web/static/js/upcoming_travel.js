/**
 * Upcoming Travel Vue application
 * Displays travel records in a structured format
 */

document.addEventListener('DOMContentLoaded', function() {
    new Vue({
        el: '#app',
        data: {
            // Use the global variable defined in the HTML
            travelData: travelRecordsData || {},
            loading: false
        },
        computed: {
            isEmpty() {
                return !this.travelData || Object.keys(this.travelData).length === 0;
            }
        },
        methods: {
            formatDate(dateString) {
                // Format dates if needed
                if (!dateString) return '';
                const date = new Date(dateString);
                return date.toLocaleDateString();
            },
            
            formatLocation(location) {
                // Format location if needed
                return location || 'N/A';
            },
            
            formatStatus(status) {
                // Add status formatting if needed
                return status || 'N/A';
            }
        }
    });
});
