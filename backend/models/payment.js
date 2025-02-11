const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: [0.01, 'Amount must be greater than zero']
    },
    paymentMethod: {
        type: String,
        enum: {
            values: ['stripe', 'paypal'],
            message: '{VALUE} is not a valid payment method'
        },
        required: true
    },
    status: {
        type: String,
        enum: {
            values: ['pending', 'approved', 'rejected'],
            message: '{VALUE} is not a valid payment status'
        },
        default: 'pending'
    },
    paymentDetails: {
        type: {
            cardLast4: String,
            expiryDate: String,
            paypalEmail: String
        },
        validate: {
            validator: function(v) {
                // Validate payment details based on payment method
                if (this.paymentMethod === 'stripe') {
                    return v.cardLast4 && v.expiryDate;
                } else if (this.paymentMethod === 'paypal') {
                    return v.paypalEmail;
                }
                return false;
            },
            message: 'Invalid payment details for the selected payment method'
        }
    },
    createdAt: {
        type: Date,
        default: Date.now,
        immutable: true // Prevents modification of creation timestamp
    }
}, {
    // Add mongoose schema options
    timestamps: true, // Adds updatedAt field
    strict: true // Enforce schema validation
});

// Optional: Add an index for faster querying
paymentSchema.index({ user: 1, createdAt: -1 });

module.exports = mongoose.model('Payment', paymentSchema);